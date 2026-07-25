import base64
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from ghostmcp.dashboard import app, generate_html_report


class DashboardSecurityTests(unittest.TestCase):
    def test_dashboard_is_locked_without_credentials(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GHOSTMCP_DASHBOARD_AUTH_PASSWORD": "",
                "GHOSTMCP_DASHBOARD_AUTH_TOKEN": "",
            },
        ):
            response = TestClient(app).get("/does-not-exist")
        self.assertEqual(response.status_code, 503)

    def test_bearer_auth_reaches_application_and_sets_security_headers(self) -> None:
        with patch.dict(
            os.environ,
            {"GHOSTMCP_DASHBOARD_AUTH_TOKEN": "test-token"},
        ):
            response = TestClient(app).get(
                "/does-not-exist",
                headers={"Authorization": "Bearer test-token"},
            )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_basic_auth_write_requires_same_origin(self) -> None:
        credentials = base64.b64encode(b"ghostmcp:test-password").decode()
        with patch.dict(
            os.environ,
            {"GHOSTMCP_DASHBOARD_AUTH_PASSWORD": "test-password"},
        ):
            response = TestClient(app).post(
                "/does-not-exist",
                headers={"Authorization": f"Basic {credentials}"},
            )
        self.assertEqual(response.status_code, 403)

    def test_html_report_escapes_stored_content(self) -> None:
        data = {
            "engagement": {
                "id": "eng-1",
                "name": "<script>alert(1)</script>",
                "status": "completed",
                "created_at": "now",
                "max_tool_level": "passive",
                "scope_cidrs": [],
                "scope_domains": [],
            },
            "stats": {
                "total_scans": 0,
                "scans_by_status": {"completed": 0, "failed": 0},
                "total_findings": 0,
                "findings_by_severity": {},
            },
            "scans": [],
            "findings": [],
        }
        rendered = generate_html_report(data)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
