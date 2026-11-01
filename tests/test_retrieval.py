import unittest

from agent_scan.scanner import scan_source


def rules_of(source: str) -> list[str]:
    return [f.rule for f in scan_source(source, "app.py") if f.verdict == "NEEDS_REVIEW"]


class RetrievedContentTest(unittest.TestCase):
    def test_fetched_page_passed_to_the_model_is_traced(self):
        source = (
            "import requests\n"
            "from agents import Agent, Runner\n"
            "def summarise(url):\n"
            "    page = requests.get(url).text\n"
            "    return Runner.run_sync(Agent(name='a', instructions='x'), page)\n"
        )
        findings = [f for f in scan_source(source, "app.py") if f.rule == "untrusted-content-to-model-input"]
        self.assertEqual(len(findings), 1)
        self.assertIn("untrusted content fetched by requests.get()", " ".join(findings[0].trace))

    def test_urlopen_content_passed_to_the_model_is_traced(self):
        source = (
            "import urllib.request\n"
            "from agents import Runner\n"
            "def run(url, agent):\n"
            "    body = urllib.request.urlopen(url).read()\n"
            "    return Runner.run(agent, body)\n"
        )
        self.assertIn("untrusted-content-to-model-input", rules_of(source))

    def test_a_literal_prompt_is_not_traced(self):
        source = (
            "import requests\n"
            "from agents import Runner\n"
            "def run(agent):\n"
            "    page = requests.get('https://example.com').text\n"
            "    return Runner.run_sync(agent, 'Summarise the policy.')\n"
        )
        self.assertNotIn("untrusted-content-to-model-input", rules_of(source))

    def test_fetched_content_that_never_reaches_the_model_is_not_reported(self):
        source = (
            "import requests\n"
            "def save(url):\n"
            "    page = requests.get(url).text\n"
            "    open('out.txt', 'w').write(page)\n"
        )
        self.assertNotIn("untrusted-content-to-model-input", rules_of(source))

    def test_fetched_content_reaching_a_shell_is_traced_as_a_shell_flow(self):
        source = (
            "import requests, subprocess\n"
            "def run(url):\n"
            "    cmd = requests.get(url).text\n"
            "    subprocess.run(cmd)\n"
        )
        self.assertIn("tainted-value-to-sink", rules_of(source))
