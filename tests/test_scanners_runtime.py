import unittest

from ghostmcp.scanners import ScannerError, ScannerTimeoutError, run_external_binary


class ScannerRuntimeTests(unittest.TestCase):
    def test_command_redaction_hides_sensitive_values(self) -> None:
        from ghostmcp.scanners import _redact_command

        command = [
            "sqlmap",
            "--auth-cred=user:secret",
            "--token",
            "token-value",
        ]
        self.assertEqual(
            _redact_command(command),
            [
                "sqlmap",
                "--auth-cred=<redacted>",
                "--token",
                "<redacted>",
            ],
        )

    def test_smbmap_password_is_redacted(self) -> None:
        from ghostmcp.scanners import _redact_command

        self.assertEqual(
            _redact_command(
                ["smbmap", "-H", "10.0.0.2", "-u", "u", "-p", "secret"]
            ),
            [
                "smbmap",
                "-H",
                "10.0.0.2",
                "-u",
                "u",
                "-p",
                "<redacted>",
            ],
        )

    def test_missing_binary(self) -> None:
        with self.assertRaises(ScannerError):
            run_external_binary("__ghostmcp_missing_binary__")

    def test_timeout_enforced(self) -> None:
        with self.assertRaises(ScannerTimeoutError):
            run_external_binary("sh", ["-c", "sleep 2"], timeout_s=0.1)

    def test_output_truncation(self) -> None:
        result = run_external_binary(
            "sh",
            ["-c", "for i in $(seq 1 2000); do echo X; done"],
            timeout_s=5,
            max_stdout_bytes=128,
            max_stderr_bytes=64,
        )
        self.assertIn("output_truncated", result)
        self.assertLessEqual(len(result["stdout"].encode("utf-8")), 128)


if __name__ == "__main__":
    unittest.main()
