import unittest
from pathlib import Path


class WorkflowConfigTests(unittest.TestCase):
    def test_required_workflow_files_exist(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertTrue((root / ".github/workflows/ci.yml").exists())
        self.assertTrue((root / ".github/workflows/codeql.yml").exists())
        self.assertTrue((root / ".github/workflows/release.yml").exists())
        self.assertTrue((root / ".github/dependabot.yml").exists())

    def test_ci_workflow_has_quality_checks(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("ruff check .", text)
        self.assertIn("mypy ghostmcp", text)
        self.assertIn("python -m unittest discover -s tests", text)

    def test_release_workflow_has_provenance_and_sbom(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("actions/attest-build-provenance", text)
        self.assertIn("anchore/sbom-action", text)


if __name__ == "__main__":
    unittest.main()
