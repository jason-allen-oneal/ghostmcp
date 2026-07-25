import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ghostmcp.credentials import EncryptedCredentialStore
from ghostmcp.proxy import (
    ProxyConfigurationError,
    apply_proxy_mode,
    validate_proxy_configuration,
)
from ghostmcp.scanners import run_external_binary


class RuntimeHardeningTests(unittest.TestCase):
    def test_proxychains_configuration_fails_closed(self) -> None:
        with patch.dict(os.environ, {"GHOSTMCP_PROXY_MODE": "proxychains"}):
            with patch("ghostmcp.proxy.shutil.which", return_value=None):
                with self.assertRaises(ProxyConfigurationError):
                    apply_proxy_mode(["example-tool"])

    def test_required_route_rejects_none(self) -> None:
        with patch.dict(os.environ, {"GHOSTMCP_PROXY_MODE": "none"}):
            with self.assertRaises(ProxyConfigurationError):
                validate_proxy_configuration(required=True)

    def test_subprocess_environment_does_not_inherit_arbitrary_secrets(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GHOSTMCP_TEST_SECRET": "do-not-inherit",
                "GHOSTMCP_PROXY_MODE": "none",
            },
        ):
            result = run_external_binary("env")
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("do-not-inherit", result["stdout"])

    def test_subprocess_result_reports_failure_and_redacts_output(self) -> None:
        with patch.dict(os.environ, {"GHOSTMCP_PROXY_MODE": "none"}):
            result = run_external_binary(
                "sh",
                ["-c", "printf 'password=supersecret'; exit 2"],
            )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["exit_code"], 2)
        self.assertNotIn("supersecret", result["stdout"])
        self.assertNotIn("supersecret", " ".join(result["command"]))

    def test_encrypted_credential_files_are_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "credentials.bin"
            store = EncryptedCredentialStore(str(store_path))
            store.set_credentials("example", {"token": "sensitive"})
            key_path = Path(f"{store_path}.key")

            self.assertEqual(stat.S_IMODE(store_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertNotIn(b"sensitive", store_path.read_bytes())

    def test_credential_store_does_not_write_on_construction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "credentials.bin"
            EncryptedCredentialStore(str(store_path))
            self.assertFalse(store_path.exists())
            self.assertFalse(Path(f"{store_path}.key").exists())


if __name__ == "__main__":
    unittest.main()
