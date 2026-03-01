"""
IMAP adapter for chatgpt_register.py.

Usage:
  python chatgpt_register_imap.py

Required config keys in config.json (or env vars):
  imap_host / IMAP_HOST
  imap_port / IMAP_PORT (default 993)
  imap_user / IMAP_USER
  imap_pass / IMAP_PASS
  email_domain / EMAIL_DOMAIN  (or fixed_email / FIXED_EMAIL)
Optional:
  email_prefix / EMAIL_PREFIX (default "auto")
  imap_folder / IMAP_FOLDER (default "INBOX")
  imap_ssl / IMAP_SSL (default true)
"""

import email as py_email
import imaplib
import os
import random
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.header import decode_header
from email.utils import parsedate_to_datetime

# Suppress DuckMail-required startup warning in the base module.
os.environ.setdefault("DUCKMAIL_BEARER", "__IMAP_MODE__")
import chatgpt_register as base


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


IMAP_HOST = os.environ.get("IMAP_HOST", str(base._CONFIG.get("imap_host", "")).strip())
IMAP_PORT = int(os.environ.get("IMAP_PORT", str(base._CONFIG.get("imap_port", 993) or 993)))
IMAP_USER = os.environ.get("IMAP_USER", str(base._CONFIG.get("imap_user", "")).strip())
IMAP_PASS = os.environ.get("IMAP_PASS", str(base._CONFIG.get("imap_pass", "")).strip())
IMAP_FOLDER = os.environ.get("IMAP_FOLDER", str(base._CONFIG.get("imap_folder", "INBOX")).strip() or "INBOX")
IMAP_SSL = _as_bool(os.environ.get("IMAP_SSL", base._CONFIG.get("imap_ssl", True)))

EMAIL_DOMAIN = os.environ.get("EMAIL_DOMAIN", str(base._CONFIG.get("email_domain", "")).strip())
EMAIL_PREFIX = os.environ.get("EMAIL_PREFIX", str(base._CONFIG.get("email_prefix", "auto")).strip() or "auto")
FIXED_EMAIL = os.environ.get("FIXED_EMAIL", str(base._CONFIG.get("fixed_email", "")).strip())
IMAP_STRICT_TARGET_MATCH = _as_bool(os.environ.get("IMAP_STRICT_TARGET_MATCH", base._CONFIG.get("imap_strict_target_match", True)))
IMAP_ALLOW_FALLBACK_MATCH = _as_bool(os.environ.get("IMAP_ALLOW_FALLBACK_MATCH", base._CONFIG.get("imap_allow_fallback_match", False)))
IMAP_SERIAL_OTP = _as_bool(os.environ.get("IMAP_SERIAL_OTP", base._CONFIG.get("imap_serial_otp", True)))


def _has_imap_config():
    has_login = bool(IMAP_HOST and IMAP_USER and IMAP_PASS)
    has_target = bool(FIXED_EMAIL or EMAIL_DOMAIN)
    return has_login and has_target


class ChatGPTRegisterIMAP(base.ChatGPTRegister):
    def __init__(self, proxy=None, tag=""):
        super().__init__(proxy=proxy, tag=tag)
        self._imap_cache_lock = threading.Lock()
        self._imap_detail_cache = {}

    def _decode_mime(self, value):
        if not value:
            return ""
        parts = decode_header(value)
        out = []
        for text, enc in parts:
            if isinstance(text, bytes):
                try:
                    out.append(text.decode(enc or "utf-8", errors="replace"))
                except Exception:
                    out.append(text.decode("utf-8", errors="replace"))
            else:
                out.append(str(text))
        return "".join(out)

    def _extract_mail_bodies(self, msg):
        text_chunks = []
        html_chunks = []
        if msg.is_multipart():
            for part in msg.walk():
                ctype = (part.get_content_type() or "").lower()
                if ctype not in ("text/plain", "text/html"):
                    continue
                try:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                except Exception:
                    try:
                        decoded = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
                    except Exception:
                        continue
                if ctype == "text/html":
                    html_chunks.append(decoded)
                else:
                    text_chunks.append(decoded)
        else:
            try:
                payload = msg.get_payload(decode=True) or b""
                charset = msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                try:
                    decoded = (msg.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
                except Exception:
                    decoded = ""
            ctype = (msg.get_content_type() or "").lower()
            if ctype == "text/html":
                html_chunks.append(decoded)
            else:
                text_chunks.append(decoded)
        return "\n".join(text_chunks), "\n".join(html_chunks)

    def _scan_imap_for_target(self, target_email, limit=40):
        conn = None
        target = str(target_email or "").strip().lower()
        target_url = target.replace("@", "%40") if target else ""
        msg_list = []
        detail_map = {}
        try:
            if IMAP_SSL:
                conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
            else:
                conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
            conn.login(IMAP_USER, IMAP_PASS)
            conn.select(IMAP_FOLDER, readonly=True)
            status, data = conn.search(None, "ALL")
            if status != "OK" or not data or not data[0]:
                return [], {}

            ids = data[0].split()[-limit:]
            ids.reverse()
            now_ts = time.time()

            strict_candidates = []
            fallback_candidates = []
            for uid in ids:
                status, msg_data = conn.fetch(uid, "(RFC822)")
                if status != "OK" or not msg_data:
                    continue

                raw = None
                for part in msg_data:
                    if isinstance(part, tuple) and len(part) >= 2:
                        raw = part[1]
                        break
                if not raw:
                    continue

                msg = py_email.message_from_bytes(raw)
                subject = self._decode_mime(msg.get("Subject", ""))
                sender = self._decode_mime(msg.get("From", ""))
                to_ = self._decode_mime(msg.get("To", ""))
                cc = self._decode_mime(msg.get("Cc", ""))
                bcc = self._decode_mime(msg.get("Bcc", ""))
                delivered_to = " ".join([self._decode_mime(v) for v in msg.get_all("Delivered-To", [])])
                original_to = " ".join([self._decode_mime(v) for v in msg.get_all("X-Original-To", [])])
                forwarded_to = " ".join([self._decode_mime(v) for v in msg.get_all("X-Forwarded-To", [])])

                date_hdr = msg.get("Date", "")
                try:
                    msg_dt = parsedate_to_datetime(date_hdr)
                    msg_ts = msg_dt.timestamp()
                except Exception:
                    msg_ts = now_ts
                if now_ts - msg_ts > 900:
                    continue

                subject_l = subject.lower()
                sender_l = sender.lower()
                likely_openai = (
                    "openai" in sender_l
                    or "chatgpt" in sender_l
                    or "openai" in subject_l
                    or "verification" in subject_l
                    or "verify" in subject_l
                )
                if not likely_openai:
                    continue

                text_body, html_body = self._extract_mail_bodies(msg)
                merged = f"{subject}\n{text_body}\n{html_body}".lower()
                recipient_text = " ".join([to_, cc, bcc, delivered_to, original_to, forwarded_to]).lower()
                target_hit_headers = bool(target and (target in recipient_text or (target_url and target_url in recipient_text)))
                target_hit_body = bool(target and (target in merged or (target_url and target_url in merged)))
                target_matched = target_hit_headers or target_hit_body

                if IMAP_STRICT_TARGET_MATCH and target and not target_matched:
                    if not IMAP_ALLOW_FALLBACK_MATCH:
                        continue

                msg_id = uid.decode() if isinstance(uid, bytes) else str(uid)
                item = (msg_id, text_body, html_body)
                if target_matched:
                    strict_candidates.append(item)
                else:
                    fallback_candidates.append(item)

            selected = strict_candidates if strict_candidates else fallback_candidates
            if strict_candidates:
                self._print(f"[IMAP] target-matched mails: {len(strict_candidates)}")
            elif fallback_candidates:
                self._print(f"[IMAP] warning: using fallback mails: {len(fallback_candidates)}")

            for msg_id, text_body, html_body in selected:
                msg_list.append({"id": msg_id})
                detail_map[msg_id] = {"text": text_body, "html": html_body}

            return msg_list, detail_map
        except Exception as e:
            self._print(f"[IMAP] scan failed: {e}")
            return [], {}
        finally:
            if conn:
                try:
                    conn.logout()
                except Exception:
                    pass

    def _generate_alias_email(self):
        if FIXED_EMAIL:
            return FIXED_EMAIL
        return f"{EMAIL_PREFIX}{random.randint(10000, 99999)}@{EMAIL_DOMAIN}"

    def create_temp_email(self):
        alias = self._generate_alias_email()
        return alias, "(imap-receiver)", {"type": "imap", "target_email": alias}

    def _fetch_emails_duckmail(self, mail_token):
        if isinstance(mail_token, dict) and mail_token.get("type") == "imap":
            target = mail_token.get("target_email", "")
            msgs, details = self._scan_imap_for_target(target)
            with self._imap_cache_lock:
                self._imap_detail_cache = details
            return msgs
        return super()._fetch_emails_duckmail(mail_token)

    def _fetch_email_detail_duckmail(self, mail_token, msg_id):
        if isinstance(mail_token, dict) and mail_token.get("type") == "imap":
            key = str(msg_id).split("/")[-1]
            with self._imap_cache_lock:
                cached = self._imap_detail_cache.get(key)
            if cached:
                return cached
            # fallback: refresh once
            target = mail_token.get("target_email", "")
            _, details = self._scan_imap_for_target(target)
            with self._imap_cache_lock:
                self._imap_detail_cache = details
            return self._imap_detail_cache.get(key)
        return super()._fetch_email_detail_duckmail(mail_token, msg_id)


def _register_one(idx, total, proxy, output_file):
    reg = None
    try:
        reg = ChatGPTRegisterIMAP(proxy=proxy, tag=f"{idx}")
        reg._print("[IMAP] preparing alias email...")
        email_addr, email_pwd, mail_ref = reg.create_temp_email()
        tag = email_addr.split("@")[0]
        reg.tag = tag

        chatgpt_password = base._generate_password()
        name = base._random_name()
        birthdate = base._random_birthdate()

        with base._print_lock:
            print(f"\n{'='*60}")
            print(f"  [{idx}/{total}] 注册: {base._mask_email(email_addr)}")
            print(f"  ChatGPT密码: {base._mask_text(chatgpt_password, 2, 2)}")
            print(f"  邮箱密码: {base._mask_text(email_pwd, 2, 2)}")
            print(f"  姓名: {name} | 生日: {birthdate}")
            print(f"{'='*60}")

        reg.run_register(email_addr, chatgpt_password, name, birthdate, mail_ref)

        oauth_ok = True
        if base.ENABLE_OAUTH:
            reg._print("[OAuth] 获取 Codex Token...")
            tokens = reg.perform_codex_oauth_login_http(email_addr, chatgpt_password, mail_token=mail_ref)
            oauth_ok = bool(tokens and tokens.get("access_token"))
            if oauth_ok:
                base._save_codex_tokens(email_addr, tokens)
            else:
                msg = "OAuth 获取失败"
                if base.OAUTH_REQUIRED:
                    raise Exception(f"{msg}（oauth_required=true）")
                reg._print(f"[OAuth] {msg}（按配置继续）")

        with base._file_lock:
            with open(output_file, "a", encoding="utf-8") as out:
                out.write(f"{email_addr}----{chatgpt_password}----{email_pwd}----oauth={'ok' if oauth_ok else 'fail'}\n")

        with base._print_lock:
            print(f"\n[OK] [{tag}] {base._mask_email(email_addr)} 注册成功!")
        return True, email_addr, None
    except Exception as e:
        err = str(e)
        with base._print_lock:
            print(f"\n[FAIL] [{idx}] 注册失败: {base._redact_text(err)}")
            traceback.print_exc()
        return False, None, err


def run_batch(total_accounts=3, output_file="registered_accounts.txt", max_workers=3, proxy=None):
    if not _has_imap_config():
        print("[Error] IMAP config is incomplete.")
        print("Need: imap_host/imap_user/imap_pass + (email_domain or fixed_email)")
        return

    actual_workers = min(max_workers, total_accounts)
    if IMAP_SERIAL_OTP and actual_workers > 1:
        print("[IMAP] serial OTP mode enabled; forcing workers=1 to avoid OTP cross-match.")
        actual_workers = 1
    before_stats = base.collect_pool_stats(output_file=output_file)
    print(f"\n{'#'*60}")
    print("  ChatGPT Batch Register (IMAP mode)")
    print(f"  Accounts: {total_accounts} | Workers: {actual_workers}")
    print(f"  IMAP: {IMAP_HOST}:{IMAP_PORT} / {base._mask_email(IMAP_USER)}")
    print(f"  Alias: {base._mask_email(FIXED_EMAIL) if FIXED_EMAIL else f'{EMAIL_PREFIX}xxxxx@{EMAIL_DOMAIN}'}")
    print(
        f"  Token Verify: {'ON' if base.VERIFY_TOKEN_ON_REGISTER else 'OFF'}"
        f"{f' | model: {base.VERIFY_TOKEN_MODEL}' if base.VERIFY_TOKEN_ON_REGISTER else ''}"
    )
    print(f"{'#'*60}\n")

    success = 0
    fail = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        futures = {
            executor.submit(_register_one, i, total_accounts, proxy, output_file): i
            for i in range(1, total_accounts + 1)
        }
        for f in as_completed(futures):
            idx = futures[f]
            try:
                ok, _, err = f.result()
                if ok:
                    success += 1
                else:
                    fail += 1
                    print(f"  [账号 {idx}] 失败: {err}")
            except Exception as e:
                fail += 1
                print(f"  [账号 {idx}] 线程异常: {e}")

    elapsed = time.time() - start
    print(f"\nDone. success={success} fail={fail} elapsed={elapsed:.1f}s")
    if base.CODEX_MANAGER_ENABLED:
        base.sync_all_tokens_to_codex_manager()
    after_stats = base.collect_pool_stats(output_file=output_file)
    run_added_unique = max(0, int(after_stats.get("pool_unique", 0)) - int(before_stats.get("pool_unique", 0)))
    base.print_pool_stats(
        run_total=total_accounts,
        run_success=success,
        run_fail=fail,
        run_added_unique=run_added_unique,
        output_file=output_file,
    )


def main():
    print("=" * 60)
    print("  ChatGPT Batch Register (IMAP adapter)")
    print("=" * 60)

    if not _has_imap_config():
        print("[Error] Missing IMAP config in config.json or env vars.")
        return

    proxy = base.DEFAULT_PROXY
    if proxy:
        use_default = input(f"Use default proxy {base._redact_text(proxy)}? (Y/n): ").strip().lower()
        if use_default == "n":
            proxy = input("Proxy (blank=no proxy): ").strip() or None
    else:
        proxy = input("Proxy (blank=no proxy): ").strip() or None

    count_input = input(f"Accounts (default {base.DEFAULT_TOTAL_ACCOUNTS}): ").strip()
    total_accounts = int(count_input) if count_input.isdigit() and int(count_input) > 0 else base.DEFAULT_TOTAL_ACCOUNTS
    workers_input = input("Workers (default 3): ").strip()
    workers = int(workers_input) if workers_input.isdigit() and int(workers_input) > 0 else 3

    run_batch(total_accounts=total_accounts, output_file=base.DEFAULT_OUTPUT_FILE, max_workers=workers, proxy=proxy)


if __name__ == "__main__":
    main()
