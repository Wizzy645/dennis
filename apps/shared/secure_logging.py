import os
import json
import struct
import logging
import base64
from logging import Handler, Formatter, Filter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _load_log_key() -> bytes:
    b64 = os.environ.get("LOG_ENCRYPTION_KEY")
    if not b64:
        raise RuntimeError("LOG_ENCRYPTION_KEY environment variable is not set")
    key = base64.b64decode(b64)
    if len(key) != 32:
        raise ValueError("LOG_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key

class EncryptedLogHandler(Handler):
    """
    Writes AES-256-GCM encrypted records as length-prefixed binary frames:
    [4-byte nonce length][nonce][4-byte ciphertext length][ciphertext]
    """
    def __init__(self, filename: str, key: bytes = None):
        super().__init__()
        self.key = key or _load_log_key()
        self.filename = filename
        os.makedirs(os.path.dirname(os.path.abspath(filename)) or ".", exist_ok=True)
        self._file = open(filename, "ab")
        # Tests may attach this handler without a formatter; default to JSON output
        if self.formatter is None:
            self.setFormatter(JSONFormatter())

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            nonce = os.urandom(12)
            aesgcm = AESGCM(self.key)
            ciphertext = aesgcm.encrypt(nonce, msg.encode("utf-8"), None)
            frame = (
                struct.pack("!I", len(nonce)) + nonce +
                struct.pack("!I", len(ciphertext)) + ciphertext
            )
            self._file.write(frame)
            self._file.flush()
        except Exception:
            self.handleError(record)

    def close(self):
        try:
            if getattr(self, "_file", None) is not None:
                try:
                    self._file.flush()
                finally:
                    self._file.close()
        finally:
            self._file = None
            super().close()

class JSONFormatter(Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "ts": self.formatTime(record),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
            "src": f"{record.filename}:{record.lineno}",
        }
        extra = {
            k: v for k, v in record.__dict__.items()
            if k not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message", "asctime",
            }
        }
        if extra:
            log_obj["ctx"] = extra
        return json.dumps(log_obj, default=str)

class SensitiveDataFilter(Filter):
    """Redact known sensitive patterns from log messages."""
    BLOCKED = ["-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"]
    def filter(self, record: logging.LogRecord) -> bool:
        msg = str(record.getMessage())
        if any(blocked in msg for blocked in self.BLOCKED):
            record.msg = "[REDACTED]"
            record.args = ()
        return True

def _allow_plaintext_fallback() -> bool:
    """
    Default is fail-closed: do not write plaintext audit logs if the encrypted audit
    handler cannot initialize (e.g., missing LOG_ENCRYPTION_KEY).
    """
    val = os.getenv("ALLOW_PLAINTEXT_AUDIT_FALLBACK", "false").strip().lower()
    return val in {"1", "true", "yes", "y", "on"}


def get_audit_logger(name: str, log_file: str = "logs/audit.enc.log") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Idempotency / handler deduplication:
    # - avoid adding multiple console handlers
    # - avoid adding multiple encrypted handlers writing to the same file
    existing_handlers = list(getattr(logger, "handlers", []))

    def _has_console_handler() -> bool:
        for h in existing_handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
                # Formatter/filter are set below; identity is what's important for dedupe.
                return True
        return False

    def _has_encrypted_handler() -> bool:
        for h in existing_handlers:
            if isinstance(h, EncryptedLogHandler) and getattr(h, "filename", None) == log_file:
                return True
        return False

    if not _has_console_handler():
        console = logging.StreamHandler()
        console.setFormatter(JSONFormatter())
        console.addFilter(SensitiveDataFilter())
        logger.addHandler(console)

    if not _has_encrypted_handler():
        try:
            enc_handler = EncryptedLogHandler(log_file)
            enc_handler.setFormatter(JSONFormatter())
            enc_handler.addFilter(SensitiveDataFilter())
            logger.addHandler(enc_handler)
        except RuntimeError as exc:
            if not _allow_plaintext_fallback():
                raise
            plain = logging.FileHandler(log_file.replace(".enc.", ".plain."))
            plain.setFormatter(JSONFormatter())
            plain.addFilter(SensitiveDataFilter())
            logger.addHandler(plain)
            logger.warning("Falling back to plaintext audit log (explicitly enabled): %s", exc)

    logger._secure_audit_initialized = True
    return logger
