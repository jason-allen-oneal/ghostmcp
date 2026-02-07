import unittest

from ghostmcp.scanners import ScannerError, ScannerTimeoutError, run_external_binary


class ScannerRuntimeTests(unittest.TestCase):
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
