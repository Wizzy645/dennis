import os
import json
import struct
import base64
import unittest
import tempfile
from unittest.mock import patch
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from apps.shared.secure_logging import EncryptedLogHandler, JSONFormatter, get_audit_logger
from apps.common.jwt_auth import _jwt_secret
import jwt

# Must be set before importing apps that initialize the audit logger at import-time.
os.environ.setdefault("LOG_ENCRYPTION_KEY", base64.b64encode(b"\x00" * 32).decode())

# Must be set before jwt_auth._jwt_secret() is called.
os.environ.setdefault("JWT_SHARED_SECRET", "dev_secret_key_hr7382yhf9283yhf")

from apps.key_management_server.main import app as kms_app
from apps.core_app.main import app as core_app

def _read_encrypted_log(path: str):
    key = base64.b64decode(os.environ["LOG_ENCRYPTION_KEY"])
    records = []
    with open(path, "rb") as f:
        while True:
            nonce_len_bytes = f.read(4)
            if len(nonce_len_bytes) == 0:
                break
            nonce_len = struct.unpack("!I", nonce_len_bytes)[0]
            nonce = f.read(nonce_len)
            ct_len = struct.unpack("!I", f.read(4))[0]
            ciphertext = f.read(ct_len)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            records.append(json.loads(plaintext.decode("utf-8")))
    return records

class TestKMSLogging(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tempdir.name, "kms_test.enc.log")
        self.client = TestClient(kms_app)
        self.logger = get_audit_logger("kms_test_logger", self.log_path)
        # Tests attach handlers directly; keep this deterministic.
        self.logger.handlers = []
        self.logger.addHandler(EncryptedLogHandler(self.log_path))

    def tearDown(self):
        # Ensure encrypted log file handles are released on Windows before temp cleanup.
        import logging as _logging
        for h in list(getattr(self.logger, "handlers", [])):
            try:
                h.close()
            finally:
                try:
                    self.logger.removeHandler(h)
                except Exception:
                    pass

        # Also close any module-level audit handlers created at import-time
        # (e.g., apps.key_management_server.main.logger writing to logs/kms_audit.enc.log).
        for _, logger_obj in list(_logging.Logger.manager.loggerDict.items()):
            if not isinstance(logger_obj, _logging.Logger):
                continue
            for h in list(getattr(logger_obj, "handlers", [])):
                try:
                    h.close()
                except Exception:
                    pass
                try:
                    logger_obj.removeHandler(h)
                except Exception:
                    pass

        _logging.shutdown()
        self.tempdir.cleanup()

    def test_dek_generation_logs_via_testclient(self):
        with patch("apps.key_management_server.main.logger", self.logger):
            response = self.client.post("/v1/tenants/tenant-1/dek/generate")
        self.assertEqual(response.status_code, 200)
        self.assertIn("dek_hex", response.json())
        logs = _read_encrypted_log(self.log_path)
        self.assertTrue(any(
            rec.get("msg") == "dek_generated" and rec.get("ctx", {}).get("tenant_id") == "tenant-1"
            for rec in logs
        ))

    def test_tamper_detection_in_encrypted_audit_log(self):
        with patch("apps.key_management_server.main.logger", self.logger):
            response = self.client.post("/v1/tenants/tenant-1/dek/generate")
        self.assertEqual(response.status_code, 200)

        # Corrupt the log by flipping a byte in the middle of the file.
        with open(self.log_path, "r+b") as f:
            data = bytearray(f.read())
            self.assertGreater(len(data), 10)
            mid = len(data) // 2
            data[mid] = (data[mid] + 1) % 256
            f.seek(0)
            f.write(data)
            f.truncate()

        # Decrypting should fail due to GCM tag mismatch.
        with self.assertRaises(Exception):
            _read_encrypted_log(self.log_path)

    def test_logger_handler_deduplication(self):
        # get_audit_logger should not attach duplicate handlers for the same name/file.
        # Use a fresh logger name to avoid cross-test pollution.
        tmp_logger = get_audit_logger("kms_dedup_test_logger", self.log_path)
        # Ensure idempotent call doesn't increase handler count.
        initial = len(getattr(tmp_logger, "handlers", []))
        tmp_logger = get_audit_logger("kms_dedup_test_logger", self.log_path)
        after = len(getattr(tmp_logger, "handlers", []))
        self.assertEqual(initial, after)

    def test_kms_decrypt_failure_on_invalid_dek_hex(self):
        # Invalid hex currently bubbles up as a ValueError from bytes.fromhex()
        # (endpoint has no explicit error handling for malformed input).
        with patch("apps.key_management_server.main.logger", self.logger):
            with self.assertRaises(ValueError):
                self.client.post(
                    "/v1/tenants/tenant-1/dek/decrypt",
                    json={"encrypted_dek_hex": "not-hex-at-all"},
                )

    def test_audit_frame_boundary_tamper_detection(self):
        # Corrupt the first frame's length prefix (nonce length) so parsing/decryption fails.
        with patch("apps.key_management_server.main.logger", self.logger):
            resp = self.client.post("/v1/tenants/tenant-1/dek/generate")
        self.assertEqual(resp.status_code, 200)

        with open(self.log_path, "r+b") as f:
            data = bytearray(f.read())
            self.assertGreaterEqual(len(data), 8)

            # nonce_len is a 4-byte big-endian int at the start of the file.
            # Set it to an invalid large value to break frame boundaries.
            data[0:4] = struct.pack("!I", 0xFFFFFFF0)
            f.seek(0)
            f.write(data)
            f.truncate()

        with self.assertRaises(Exception):
            _read_encrypted_log(self.log_path)

def _make_jwt(tenant_id: str, subject: str = "test-subject") -> str:
    return jwt.encode(
        {"sub": subject, "tenant_id": tenant_id, "iss": os.getenv("JWT_ISSUER", "local-emr-auth-service")},
        _jwt_secret(),
        algorithm="HS256",
    )
class TestCoreAppLogging(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tempdir.name, "core_test.enc.log")
        self.client = TestClient(core_app)
        self.logger = get_audit_logger("core_test_logger", self.log_path)
        self.logger.handlers = []
        self.logger.addHandler(EncryptedLogHandler(self.log_path))
        with patch("apps.core_app.main.logger", self.logger):
            r = self.client.post("/v1/admin/tenants/tenant-2/provision")
        self.assertEqual(r.status_code, 200)

    def test_record_creation_requires_auth(self):
        payload = {
            "encrypted_dek_hex": "deadbeef00",
            "ciphertext_hex": "cafebabe00",
            "iv_hex": "123456789012",
            "tag_hex": "aabbccdd00",
        }
        with patch("apps.core_app.main.logger", self.logger):
            resp = self.client.post("/v1/tenants/tenant-2/records", json=payload)
        self.assertEqual(resp.status_code, 401)

    def test_record_creation_rejects_invalid_token(self):
        payload = {
            "encrypted_dek_hex": "deadbeef00",
            "ciphertext_hex": "cafebabe00",
            "iv_hex": "123456789012",
            "tag_hex": "aabbccdd00",
        }
        headers = {"Authorization": "Bearer invalid.jwt.token"}
        with patch("apps.core_app.main.logger", self.logger):
            resp = self.client.post("/v1/tenants/tenant-2/records", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_record_creation_tenant_mismatch_forbidden(self):
        payload = {
            "encrypted_dek_hex": "deadbeef00",
            "ciphertext_hex": "cafebabe00",
            "iv_hex": "123456789012",
            "tag_hex": "aabbccdd00",
        }
        token = _make_jwt("tenant-1")  # but POST to tenant-2
        headers = {"Authorization": f"Bearer {token}"}
        with patch("apps.core_app.main.logger", self.logger):
            resp = self.client.post("/v1/tenants/tenant-2/records", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 403)

    def tearDown(self):
        # Ensure encrypted log file handles are released on Windows before temp cleanup.
        import logging as _logging
        for h in list(getattr(self.logger, "handlers", [])):
            try:
                h.close()
            finally:
                try:
                    self.logger.removeHandler(h)
                except Exception:
                    pass

        for _, logger_obj in list(_logging.Logger.manager.loggerDict.items()):
            if not isinstance(logger_obj, _logging.Logger):
                continue
            for h in list(getattr(logger_obj, "handlers", [])):
                try:
                    h.close()
                except Exception:
                    pass
                try:
                    logger_obj.removeHandler(h)
                except Exception:
                    pass

        _logging.shutdown()
        self.tempdir.cleanup()

    def test_record_creation_logs_via_testclient(self):
        payload = {
            "encrypted_dek_hex": "deadbeef00",
            "ciphertext_hex": "cafebabe00",
            "iv_hex": "123456789012",
            "tag_hex": "aabbccdd00",
        }
        token = _make_jwt("tenant-2")
        headers = {"Authorization": f"Bearer {token}"}
        with patch("apps.core_app.main.logger", self.logger):
            response = self.client.post("/v1/tenants/tenant-2/records", json=payload, headers=headers)
        self.assertEqual(response.status_code, 200)
        logs = _read_encrypted_log(self.log_path)
        self.assertTrue(any(
            rec.get("msg") == "record_created" and rec.get("ctx", {}).get("tenant_id") == "tenant-2"
            for rec in logs
        ))

if __name__ == "__main__":
    unittest.main()
