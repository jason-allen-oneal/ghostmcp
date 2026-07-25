import stat
import tempfile
import unittest
from pathlib import Path

from ghostmcp.database import Database


class DatabaseSecurityTests(unittest.TestCase):
    def test_database_is_private_queryable_and_redacts_sensitive_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ghostmcp.db"
            db = Database(str(path))
            engagement = db.create_engagement(
                "eng-1",
                "Example",
                description="auth_token=do-not-store",
            )
            self.assertNotIn("do-not-store", engagement.description or "")
            scan = db.create_scan(
                "scan-1",
                engagement.id,
                "example_tool",
                "https://user:pass@example.test/path?token=secret",
                parameters={"password": "sensitive", "mode": "safe"},
            )
            db.complete_scan(
                scan.id,
                result={"api_key": "sensitive", "message": "password=secret"},
            )

            loaded = db.get_scan(scan.id)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.target, "https://example.test/path")
            self.assertEqual(loaded.parameters["password"], "[REDACTED]")
            self.assertEqual(loaded.result["api_key"], "[REDACTED]")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
