import os
import subprocess
import sys
import time
import unittest
from pathlib import Path


class E2EMCPTests(unittest.TestCase):
    @unittest.skipUnless(os.getenv("GHOSTMCP_E2E") == "1", "set GHOSTMCP_E2E=1 to run")
    def test_server_starts_and_stops(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        proc = subprocess.Popen(
            [sys.executable, "-m", "ghostmcp.server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(repo_root),
        )
        try:
            time.sleep(1.0)
            self.assertIsNone(proc.poll())
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            if proc.stdin:
                proc.stdin.close()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
