import os
import subprocess
import time
import unittest


class E2EMCPTests(unittest.TestCase):
    @unittest.skipUnless(os.getenv("GHOSTMCP_E2E") == "1", "set GHOSTMCP_E2E=1 to run")
    def test_server_starts_and_stops(self) -> None:
        proc = subprocess.Popen(
            ["ghostmcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(1.0)
            self.assertIsNone(proc.poll())
        finally:
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
