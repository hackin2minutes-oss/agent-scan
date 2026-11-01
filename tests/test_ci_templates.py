import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


class CiTemplateTest(unittest.TestCase):
    def test_gitlab_job_runs_the_scan_and_keeps_the_sarif(self):
        job = yaml.safe_load((ROOT / "ci/gitlab/sawoneai.gitlab-ci.yml").read_text(encoding="utf-8"))["sawoneai"]
        self.assertIn("sawoneai scan . --format sarif --output sawoneai.sarif", job["script"][0])
        self.assertIn("sawoneai.sarif", job["artifacts"]["paths"])
        self.assertEqual(job["image"]["entrypoint"], [""])

    def test_azure_pipeline_runs_the_scan_without_network_and_publishes_sarif(self):
        pipeline = yaml.safe_load((ROOT / "ci/azure-devops/sawoneai.azure-pipelines.yml").read_text(encoding="utf-8"))
        text = (ROOT / "ci/azure-devops/sawoneai.azure-pipelines.yml").read_text(encoding="utf-8")
        self.assertIn("--network none", text)
        self.assertIn("scan /work --format sarif --output /out/sawoneai.sarif", text)
        publish = [s for s in pipeline["steps"] if "publish" in s]
        self.assertEqual(publish[0]["artifact"], "sawoneai-sarif")

    def test_both_templates_use_the_same_command_line(self):
        gitlab = yaml.safe_load((ROOT / "ci/gitlab/sawoneai.gitlab-ci.yml").read_text(encoding="utf-8"))["sawoneai"]
        self.assertIn("scan . --format sarif --output sawoneai.sarif", gitlab["script"][0])
        azure = (ROOT / "ci/azure-devops/sawoneai.azure-pipelines.yml").read_text(encoding="utf-8")
        self.assertIn("scan /work --format sarif --output /out/sawoneai.sarif", azure)
