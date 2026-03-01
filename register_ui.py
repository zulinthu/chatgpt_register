import json
import re
import sys
from pathlib import Path

from PyQt5.QtCore import QProcess
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)


PROJECT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_DIR / "config.json"
MASK_PLACEHOLDER = "***"
SENSITIVE_KEYS = {"duckmail_bearer", "imap_pass", "upload_api_token", "codex_manager_rpc_token"}
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b")
RT_RE = re.compile(r"\brt_[A-Za-z0-9._-]+\b")
BEARER_RE = re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._~+/\-=]{8,})")
SENSITIVE_KV_RE = re.compile(
    r'(?i)((?:access_token|id_token|refresh_token|password|duckmail_bearer|upload_api_token|codex_manager_rpc_token|mail_token)\s*[=:]\s*)([^\s,]+)'
)
QUERY_PARAM_RE = re.compile(
    r"(?i)([?&](?:login_hint|state|code|device_id|ext-oai-did|auth_session_logging_id|csrfToken|oai-did|id_token|access_token|refresh_token)=)([^&\s]+)"
)
JSON_SENSITIVE_VALUE_RE = re.compile(
    r'(?i)("(?:csrfToken|state|code|device_id|auth_session_logging_id|login_hint|access_token|id_token|refresh_token)"\s*:\s*")([^"]+)(")'
)


def mask_text(value: str, head: int = 2, tail: int = 2) -> str:
    s = str(value or "")
    if not s:
        return s
    if len(s) <= head + tail:
        return "*" * len(s)
    return f"{s[:head]}{'*' * (len(s) - head - tail)}{s[-tail:]}"


def mask_email(value: str) -> str:
    s = str(value or "")
    if "@" not in s:
        return mask_text(s, 2, 2)
    local, domain = s.split("@", 1)
    return f"{mask_text(local, 2, 1)}@{mask_text(domain, 1, 3)}"


def redact_text(value: str) -> str:
    text = str(value or "")
    if not text:
        return text
    text = EMAIL_RE.sub(lambda m: mask_email(m.group(0)), text)
    text = JWT_RE.sub(lambda m: mask_text(m.group(0), 8, 6), text)
    text = RT_RE.sub(lambda m: mask_text(m.group(0), 6, 4), text)
    text = BEARER_RE.sub(lambda m: f"{m.group(1)}{mask_text(m.group(2), 6, 4)}", text)
    text = SENSITIVE_KV_RE.sub(lambda m: f"{m.group(1)}{mask_text(m.group(2), 2, 2)}", text)
    text = QUERY_PARAM_RE.sub(lambda m: f"{m.group(1)}{mask_text(m.group(2), 4, 3)}", text)
    text = JSON_SENSITIVE_VALUE_RE.sub(lambda m: f"{m.group(1)}{mask_text(m.group(2), 4, 3)}{m.group(3)}", text)
    return text


def build_runner_code(module_name: str, total_accounts: int, output_file: str, workers: int, proxy: str) -> str:
    proxy_expr = "None" if not proxy.strip() else repr(proxy.strip())
    return (
        f"import {module_name} as m; "
        f"m.run_batch(total_accounts={int(total_accounts)}, "
        f"output_file={output_file!r}, "
        f"max_workers={int(workers)}, "
        f"proxy={proxy_expr})"
    )


class RegisterUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.process = QProcess(self)
        self._loaded_config = {}
        self._setup_process()
        self._setup_ui()
        self.load_config()

    def _setup_process(self):
        self.process.readyReadStandardOutput.connect(self._on_stdout)
        self.process.readyReadStandardError.connect(self._on_stderr)
        self.process.started.connect(lambda: self._set_status("Running"))
        self.process.finished.connect(self._on_finished)

    def _setup_ui(self):
        self.setWindowTitle("ChatGPT Register UI (PyQt)")
        self.resize(1180, 760)

        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        controls_box = QGroupBox("Run Controls")
        form = QGridLayout(controls_box)

        self.python_edit = QLineEdit(sys.executable)
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("IMAP Adapter", "chatgpt_register_imap")
        self.mode_combo.addItem("DuckMail", "chatgpt_register")

        self.accounts_spin = QSpinBox()
        self.accounts_spin.setRange(1, 10000)
        self.accounts_spin.setValue(1)

        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 256)
        self.workers_spin.setValue(3)

        self.output_edit = QLineEdit("registered_accounts.txt")
        self.proxy_edit = QLineEdit("")
        self.proxy_edit.setPlaceholderText("blank means use None")

        form.addWidget(QLabel("Python"), 0, 0)
        form.addWidget(self.python_edit, 0, 1, 1, 3)
        form.addWidget(QLabel("Mode"), 1, 0)
        form.addWidget(self.mode_combo, 1, 1)
        form.addWidget(QLabel("Accounts"), 1, 2)
        form.addWidget(self.accounts_spin, 1, 3)
        form.addWidget(QLabel("Workers"), 2, 0)
        form.addWidget(self.workers_spin, 2, 1)
        form.addWidget(QLabel("Output File"), 2, 2)
        form.addWidget(self.output_edit, 2, 3)
        form.addWidget(QLabel("Proxy Override"), 3, 0)
        form.addWidget(self.proxy_edit, 3, 1, 1, 3)

        btn_row = QHBoxLayout()
        self.btn_load = QPushButton("Load Config")
        self.btn_save = QPushButton("Save Config")
        self.btn_start = QPushButton("Start")
        self.btn_stop = QPushButton("Stop")
        self.btn_clear = QPushButton("Clear Log")
        self.status_label = QLabel("Idle")

        for btn in [self.btn_load, self.btn_save, self.btn_start, self.btn_stop, self.btn_clear]:
            btn_row.addWidget(btn)
        btn_row.addStretch(1)
        btn_row.addWidget(QLabel("Status:"))
        btn_row.addWidget(self.status_label)

        controls_wrap = QVBoxLayout()
        controls_wrap.addWidget(controls_box)
        controls_wrap.addLayout(btn_row)

        cfg_widget = QWidget()
        cfg_layout = QVBoxLayout(cfg_widget)
        cfg_layout.addWidget(QLabel("config.json"))
        self.config_edit = QPlainTextEdit()
        self.config_edit.setFont(QFont("Consolas", 10))
        cfg_layout.addWidget(self.config_edit)

        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.addWidget(QLabel("Runtime Log"))
        self.log_edit = QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Consolas", 10))
        log_layout.addWidget(self.log_edit)

        splitter = QSplitter()
        splitter.addWidget(cfg_widget)
        splitter.addWidget(log_widget)
        splitter.setSizes([560, 560])

        root.addLayout(controls_wrap)
        root.addWidget(splitter, 1)

        self.btn_load.clicked.connect(self.load_config)
        self.btn_save.clicked.connect(self.save_config)
        self.btn_start.clicked.connect(self.start_run)
        self.btn_stop.clicked.connect(self.stop_run)
        self.btn_clear.clicked.connect(self.log_edit.clear)

    def _set_status(self, text: str):
        self.status_label.setText(text)

    def append_log(self, text: str):
        if not text:
            return
        text = redact_text(text)
        self.log_edit.moveCursor(QTextCursor.End)
        self.log_edit.insertPlainText(text)
        self.log_edit.moveCursor(QTextCursor.End)

    def _decode_output(self, data: bytes) -> str:
        for enc in ("utf-8", "gbk", "cp936"):
            try:
                return data.decode(enc)
            except Exception:
                pass
        return data.decode("utf-8", errors="replace")

    def _on_stdout(self):
        self.append_log(self._decode_output(bytes(self.process.readAllStandardOutput())))

    def _on_stderr(self):
        self.append_log(self._decode_output(bytes(self.process.readAllStandardError())))

    def _on_finished(self, code: int, status):
        self._set_status(f"Stopped (exit={code})")
        self.append_log(f"\n[UI] Process finished with exit code {code}\n")

    def load_config(self):
        if not CONFIG_PATH.exists():
            QMessageBox.warning(self, "Missing config", f"File not found:\n{CONFIG_PATH}")
            return
        try:
            raw = CONFIG_PATH.read_text(encoding="utf-8")
            cfg = json.loads(raw)
        except Exception as e:
            QMessageBox.critical(self, "Load failed", str(e))
            return

        self._loaded_config = dict(cfg)
        masked_cfg = dict(cfg)
        for key in SENSITIVE_KEYS:
            value = masked_cfg.get(key)
            if isinstance(value, str) and value:
                masked_cfg[key] = MASK_PLACEHOLDER
        self.config_edit.setPlainText(json.dumps(masked_cfg, ensure_ascii=False, indent=2) + "\n")

        self.accounts_spin.setValue(max(1, int(cfg.get("total_accounts", 1) or 1)))
        self.output_edit.setText(str(cfg.get("output_file", "registered_accounts.txt") or "registered_accounts.txt"))
        self.proxy_edit.setText(str(cfg.get("proxy", "") or ""))
        self._set_status("Config loaded")

    def save_config(self) -> bool:
        raw = self.config_edit.toPlainText()
        try:
            parsed = json.loads(raw)
        except Exception as e:
            QMessageBox.critical(self, "Invalid JSON", str(e))
            return False
        for key in SENSITIVE_KEYS:
            value = parsed.get(key)
            if value == MASK_PLACEHOLDER and isinstance(self._loaded_config.get(key), str):
                parsed[key] = self._loaded_config.get(key)
        try:
            CONFIG_PATH.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            self._loaded_config = dict(parsed)
        except Exception as e:
            QMessageBox.critical(self, "Save failed", str(e))
            return False
        self._set_status("Config saved")
        return True

    def start_run(self):
        if self.process.state() != QProcess.NotRunning:
            QMessageBox.information(self, "Running", "Process is already running.")
            return
        if not self.save_config():
            return

        python_path = self.python_edit.text().strip() or sys.executable
        module_name = self.mode_combo.currentData()
        accounts = self.accounts_spin.value()
        workers = self.workers_spin.value()
        output_file = self.output_edit.text().strip() or "registered_accounts.txt"
        proxy = self.proxy_edit.text().strip()
        code = build_runner_code(module_name, accounts, output_file, workers, proxy)

        self.log_edit.appendPlainText(
            f"[UI] Starting: {module_name} | accounts={accounts} workers={workers} proxy={'set' if proxy else 'none'}"
        )
        self.log_edit.appendPlainText(f"[UI] Python: {python_path}")

        self.process.setWorkingDirectory(str(PROJECT_DIR))
        self.process.start(python_path, ["-u", "-c", code])
        if not self.process.waitForStarted(4000):
            QMessageBox.critical(self, "Start failed", self.process.errorString())
            self._set_status("Start failed")
            return

    def stop_run(self):
        if self.process.state() == QProcess.NotRunning:
            return
        self.append_log("\n[UI] Stopping process...\n")
        self.process.terminate()
        if not self.process.waitForFinished(3000):
            self.process.kill()
            self.process.waitForFinished(1000)

    def closeEvent(self, event):
        self.stop_run()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    win = RegisterUI()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
