"""vibecheck/build.py: which commit a copy of the scanner was built from."""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibecheck import __version__, build  # noqa: E402
from vibecheck.cli import main  # noqa: E402
from vibecheck.report import render_json, render_markdown, render_terminal  # noqa: E402
from vibecheck.scanner import scan  # noqa: E402

SHA = "3a83b0d959af1b02ff07c562fb8001f9ea5cff1b"
OTHER = "dd834623fc298a50628619b927b994d580834b2c"


def checkout(root: Path, head: str, files: dict) -> Path:
    """A fake clone: root/.git with the given HEAD and files; returns root/vibecheck."""
    git = root / ".git"
    git.mkdir(parents=True)
    (git / "HEAD").write_text(head + "\n", encoding="utf-8")
    for name, text in files.items():
        path = git / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    package = root / "vibecheck"
    package.mkdir()
    return package


class FromCheckoutTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_branch_with_a_loose_ref(self):
        package = checkout(self.root, "ref: refs/heads/main", {"refs/heads/main": SHA + "\n"})
        self.assertEqual(build._from_checkout(package), SHA)

    def test_branch_found_in_packed_refs(self):
        packed = f"# pack-refs with: peeled fully-peeled sorted\n{OTHER} refs/heads/other\n{SHA} refs/heads/main\n"
        package = checkout(self.root, "ref: refs/heads/main", {"packed-refs": packed})
        self.assertEqual(build._from_checkout(package), SHA)

    def test_detached_head(self):
        package = checkout(self.root, SHA, {})
        self.assertEqual(build._from_checkout(package), SHA)

    def test_worktree_points_at_the_main_clone(self):
        main_git = self.root / "main" / ".git"
        wt_git = main_git / "worktrees" / "wt"
        wt_git.mkdir(parents=True)
        (wt_git / "HEAD").write_text("ref: refs/heads/feature\n", encoding="utf-8")
        (wt_git / "commondir").write_text("../..\n", encoding="utf-8")
        (main_git / "refs" / "heads").mkdir(parents=True)
        (main_git / "refs" / "heads" / "feature").write_text(SHA + "\n", encoding="utf-8")
        tree = self.root / "wt"
        (tree / "vibecheck").mkdir(parents=True)
        (tree / ".git").write_text(f"gitdir: {wt_git}\n", encoding="utf-8")
        self.assertEqual(build._from_checkout(tree / "vibecheck"), SHA)

    def test_no_git_folder(self):
        package = self.root / "vibecheck"
        package.mkdir()
        self.assertIsNone(build._from_checkout(package))

    def test_a_head_that_is_not_a_hash_is_refused(self):
        package = checkout(self.root, "ref: refs/heads/main", {"refs/heads/main": "<script>\n"})
        self.assertIsNone(build._from_checkout(package))


class FromArchiveTest(unittest.TestCase):
    def test_placeholder_left_as_written_means_not_an_archive(self):
        self.assertIsNone(build._from_archive("$Format:%H$"))

    def test_substituted_hash(self):
        self.assertEqual(build._from_archive(SHA), SHA)

    def test_this_file_is_marked_export_subst(self):
        # Without the attribute `git archive` leaves the placeholder alone and
        # the Action, which GitHub delivers as an archive, loses its commit.
        attrs = (Path(build.__file__).resolve().parent.parent / ".gitattributes")
        self.assertIn("vibecheck/build.py export-subst", attrs.read_text(encoding="utf-8"))
        self.assertIn('_ARCHIVE_COMMIT = "$Format:%H$"',
                      Path(build.__file__).read_text(encoding="utf-8"))


class FromPipTest(unittest.TestCase):
    def dist(self, location, direct_url):
        d = mock.Mock()
        d.locate_file.return_value = location
        d.read_text.return_value = direct_url
        return d

    def test_commit_from_direct_url(self):
        here = Path(build.__file__).resolve().parent
        d = self.dist(here, json.dumps({"url": "https://example.test/x", "vcs_info": {"vcs": "git", "commit_id": SHA}}))
        with mock.patch("importlib.metadata.distribution", return_value=d):
            self.assertEqual(build._from_pip(here), SHA)

    def test_an_install_somewhere_else_is_not_this_copy(self):
        here = Path(build.__file__).resolve().parent
        d = self.dist(Path("/somewhere/else/vibecheck"), json.dumps({"vcs_info": {"commit_id": SHA}}))
        with mock.patch("importlib.metadata.distribution", return_value=d):
            self.assertIsNone(build._from_pip(here))

    def test_not_installed_or_no_direct_url(self):
        here = Path(build.__file__).resolve().parent
        with mock.patch("importlib.metadata.distribution", side_effect=Exception("not installed")):
            self.assertIsNone(build._from_pip(here))
        with mock.patch("importlib.metadata.distribution", return_value=self.dist(here, None)):
            self.assertIsNone(build._from_pip(here))


class FullVersionTest(unittest.TestCase):
    def test_with_and_without_a_commit(self):
        with mock.patch.object(build, "commit", return_value=SHA):
            self.assertEqual(build.full_version(), f"{__version__}+3a83b0d")
            self.assertEqual(build.scanner_info(), {"name": "vibecheck", "version": __version__, "commit": SHA})
        with mock.patch.object(build, "commit", return_value=None):
            self.assertEqual(build.full_version(), __version__)
            self.assertIsNone(build.scanner_info()["commit"])


class ReportsCarryItTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        (Path(tmp.name) / "app.py").write_text("print('hello')\n", encoding="utf-8")
        self.result = scan(tmp.name)
        patcher = mock.patch.object(build, "commit", return_value=SHA)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.stamp = f"{__version__}+3a83b0d"

    def test_version_flag(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            main(["--version"])
        self.assertEqual(out.getvalue().strip(), f"vibecheck {self.stamp}")

    def test_terminal_markdown_and_json(self):
        self.assertIn(f"vibecheck v{self.stamp}", render_terminal(self.result, use_color=False))
        self.assertIn(f"**Scanner:** vibecheck {self.stamp}", render_markdown(self.result))
        doc = json.loads(render_json(self.result))
        self.assertEqual(doc["scanner"], {"name": "vibecheck", "version": __version__, "commit": SHA})
        self.assertIn("findings", doc)


if __name__ == "__main__":
    unittest.main()
