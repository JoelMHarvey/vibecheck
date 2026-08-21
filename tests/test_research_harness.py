"""Tests for the research harness — corpus collection and sample validity.

These matter more than they look. The scripts here decide which repositories
count as evidence, and the writeup publishes a number derived from that
choice. A filter that silently stops working doesn't crash; it just produces a
statistic that is wrong in a direction nobody notices.

The fixtures are drawn from a real 200-repo run, where roughly one target in
six turned out to be a prompt collection or a tool *about* Lovable rather than
an app built by it — and, being mostly markdown, scanned perfectly clean.
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collect = load("collect_targets")
research = load("research_scan")


# Real names from the run that should never have been in the sample.
CONTAMINANTS = [
    "x1xhlol/system-prompts-and-models-of-ai-tools",
    "KingLeoJr/prompts",
    "rtadewald/Agents-Prompts",
    "soranoo/lovable-downloader",
    "SingularityLabs-ai/Ultimate_Prompts_Directory",
    "mattnigh/ChatGPT-Free-Prompt-List",
    "thekishandev/ai-system-prompt",
    "AndreAlmeidaDC/lovable-prompt-builder",
    "hiromima/lovable-mcp-server",
    "HugoBlox/hugo-theme-developer-portfolio",
    "ddocta/2025-06-10-UMD-WNCP-AI-talk-docs",
    "dragsupplier/lovable-codebase-downloader-pro",
]

# Real names from the same run that are genuinely vibe-coded apps.
REAL_APPS = [
    "ruvnet/symbolic-scribe",
    "saisrinivas77/Smart-Study-Planner",
    "gsm-fullweb/careconnect",
    "Thabonel/wheels-wins-landing-page",
    "jpbc123/my-fengshui-calculator",
    "CYPKNFT/church-connect",
    "temikeezy/african-countries-explorer",
    "kartik7raturi/keto-compass-pro",
    "yasir870/khobzak-mobile-bakeshop-app",
    "danielmoshechkov-bit/rido-drive-smiles",
]


def repo(full, description="", **kw):
    base = {"fullName": full, "description": description,
            "isFork": False, "isArchived": False, "stargazersCount": 0}
    base.update(kw)
    return base


class TestCorpusFiltering(unittest.TestCase):
    def test_every_known_contaminant_is_rejected(self):
        for name in CONTAMINANTS:
            with self.subTest(name):
                self.assertTrue(collect.reject(repo(name)), f"{name} should be excluded")

    def test_no_real_app_is_rejected(self):
        for name in REAL_APPS:
            with self.subTest(name):
                self.assertEqual(collect.reject(repo(name)), "", f"{name} should be kept")

    def test_underscores_do_not_hide_an_excluded_word(self):
        # \b never fires around an underscore, so this used to slip past.
        self.assertTrue(collect.reject(repo("a/Ultimate_Prompts_Directory")))
        self.assertTrue(collect.reject(repo("a/Awesome_Starter_Kit")))

    def test_an_excluded_word_inside_a_longer_word_is_not_a_match(self):
        # "list" in "todo-list" is not a reason to drop someone's app.
        self.assertEqual(collect.reject(repo("a/my_todo_list_app")), "")
        self.assertEqual(collect.reject(repo("a/contemplate")), "")

    def test_forks_archived_and_vendors(self):
        self.assertEqual(collect.reject(repo("a/b", isFork=True)), "fork")
        self.assertEqual(collect.reject(repo("a/b", isArchived=True)), "archived")
        self.assertEqual(collect.reject(repo("vercel/next.js")), "vendor")

    def test_description_is_searched_too(self):
        self.assertTrue(collect.reject(repo("a/thing", "A collection of prompts")))

    def test_all_queries_are_code_searches(self):
        # Description searches conflate "built by Lovable" with "mentions
        # Lovable", which is how the prompt directories got in.
        kinds = {kind for _, _, kind in collect.QUERIES}
        self.assertEqual(kinds, {"code"})


class TestAppDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, rel, content="x"):
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def test_markdown_only_repo_is_not_an_app(self):
        for name in ("README.md", "Lovable.md", "Cursor.md", "v0.md"):
            self.write(name, "# prompts")
        self.assertFalse(research.looks_like_an_app(self.root))

    def test_a_two_file_static_page_is_an_app(self):
        # The bar is one source file, not a size threshold — a tiny static
        # site is exactly the kind of thing this research is about.
        self.write("index.html", "<html></html>")
        self.write("app.js", "console.log(1)")
        self.assertTrue(research.looks_like_an_app(self.root))

    def test_a_single_source_file_is_enough(self):
        self.write("README.md", "# docs")
        self.write("main.py", "print(1)")
        self.assertTrue(research.looks_like_an_app(self.root))

    def test_typical_generated_app_is_an_app(self):
        self.write("package.json", '{"devDependencies":{"lovable-tagger":"^1"}}')
        self.write("src/App.tsx", "export const App = () => null;")
        self.assertTrue(research.looks_like_an_app(self.root))

    def test_vendored_code_does_not_count_as_the_app(self):
        # Otherwise a markdown repo with a stray node_modules looks like code.
        self.write("README.md", "# prompts")
        self.write("node_modules/left-pad/index.js", "module.exports = 1")
        self.assertFalse(research.looks_like_an_app(self.root))

    def test_empty_repo_is_not_an_app(self):
        self.assertFalse(research.looks_like_an_app(self.root))


class TestDisclosureCount(unittest.TestCase):
    """How many repos need contacting is the number the ethics rests on.

    It cannot be recovered by adding the severity counts: those count a repo
    once per severity it contains, so a repo holding both a critical and a
    high appears in each. Adding them invents projects that don't exist and
    overstates the number of people who weren't contacted.
    """

    def repo(self, *severities):
        return {"score": 50, "grade": "D",
                "findings": [{"rule_id": f"r{i}", "severity": sev}
                             for i, sev in enumerate(severities)]}

    def test_a_repo_with_both_is_counted_once(self):
        agg = research.anonymise([self.repo("critical", "high")])
        self.assertEqual(agg["repos_with_severity"]["critical"]["count"], 1)
        self.assertEqual(agg["repos_with_severity"]["high"]["count"], 1)
        self.assertEqual(agg["repos_at_or_above_high"], 1, "counted twice")

    def test_the_union_is_smaller_than_the_sum_when_they_overlap(self):
        agg = research.anonymise([
            self.repo("critical", "high"),
            self.repo("critical"),
            self.repo("high"),
        ])
        counts = agg["repos_with_severity"]
        self.assertEqual(counts["critical"]["count"] + counts["high"]["count"], 4)
        self.assertEqual(agg["repos_at_or_above_high"], 3)

    def test_medium_and_below_do_not_need_disclosing(self):
        agg = research.anonymise([self.repo("medium", "low", "info")])
        self.assertEqual(agg["repos_at_or_above_high"], 0)

    def test_a_clean_repo_is_not_in_it(self):
        agg = research.anonymise([{"score": 100, "grade": "A", "findings": []}])
        self.assertEqual(agg["repos_at_or_above_high"], 0)


if __name__ == "__main__":
    unittest.main()
