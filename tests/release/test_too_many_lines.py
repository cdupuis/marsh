"""scripts/check-too-many-lines.sh lets the too_many_lines allow count shrink but never grow."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-too-many-lines.sh"


def check(budget, sources, vendored=""):
    with tempfile.TemporaryDirectory() as temporary:
        repo = pathlib.Path(temporary)
        (repo / "scripts").mkdir()
        shutil.copy(SCRIPT, repo / "scripts/check-too-many-lines.sh")
        (repo / "scripts/too-many-lines.budget").write_text(f"{budget}\n")
        (repo / "crates/a/src").mkdir(parents=True)
        (repo / "crates/a/src/lib.rs").write_text(sources)
        (repo / "vendor/brush").mkdir(parents=True)
        (repo / "vendor/brush/lib.rs").write_text(vendored)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        return subprocess.run(["sh", "scripts/check-too-many-lines.sh"], cwd=repo, capture_output=True, text=True)


ALLOW = "#[allow(clippy::too_many_lines)]\nfn long() {}\n"
LIST = "#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]\nfn long() {}\n"
EXPECT = '#[expect(clippy::too_many_lines, reason = "one linear sequence")]\nfn long() {}\n'


class TooManyLinesBudget(unittest.TestCase):
    def test_an_allow_over_the_budget_fails(self):
        result = check(1, ALLOW + LIST)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("2 allows", result.stderr)
        self.assertIn("budget 1", result.stderr)

    def test_allows_expects_and_list_entries_all_count(self):
        self.assertEqual(check(3, ALLOW + LIST + EXPECT).returncode, 0)
        self.assertEqual(check(2, ALLOW + LIST + EXPECT).returncode, 1)

    def test_comments_and_vendored_code_do_not_count(self):
        result = check(0, "// clippy::too_many_lines is discussed here\n", vendored=ALLOW)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_removing_an_allow_passes_and_asks_to_lower_the_budget(self):
        result = check(2, ALLOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("lower scripts/too-many-lines.budget to 1", result.stdout)

    def test_no_allows_at_all_counts_zero(self):
        self.assertEqual(check(0, "fn short() {}\n").returncode, 0)

    def test_the_repository_is_within_its_budget(self):
        result = subprocess.run(["sh", str(SCRIPT)], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
