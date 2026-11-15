"""The model README's code-location table cites code that exists."""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-model-locations.py"
README = ROOT / "docs/model/README.md"


def run(readme):
    return subprocess.run([sys.executable, str(SCRIPT), "--readme", str(readme)],
                          capture_output=True, text=True, timeout=120)


class ModelLocations(unittest.TestCase):
    def test_every_cited_file_and_identifier_exists(self):
        result = run(README)
        self.assertEqual(result.returncode, 0, result.stderr)

    def check_row(self, cell):
        table = "| Spec action | Code location |\n|---|---|\n| Workspace: Exit | " + cell + " |\n"
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "README.md"
            path.write_text(table)
            return run(path)

    def test_a_function_that_never_existed_fails(self):
        result = self.check_row("`split.rs` `branch` -> `cancel_children_of`")
        self.assertEqual(result.returncode, 1)
        self.assertIn("cancel_children_of", result.stderr)

    def test_a_missing_file_fails(self):
        result = self.check_row("`no_such_file.rs` `cancel`")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no_such_file.rs", result.stderr)

    def test_a_real_function_passes_and_prose_is_ignored(self):
        result = self.check_row("`split.rs` `cancel_lane_jobs` (break `no-such-mode`, control `noSuchControl`)")
        self.assertEqual(result.returncode, 0, result.stderr)

    def mutated(self, old, new, count=None):
        text = README.read_text()
        self.assertIn(old, text)
        text = text.replace(old, new) if count is None else text.replace(old, new, count)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "README.md"
            path.write_text(text)
            return run(path)

    def test_a_renamed_single_word_function_after_a_file_fails(self):
        result = self.mutated("`split.rs` `cancel`", "`split.rs` `canceldriftgpt`")
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not define `fn canceldriftgpt`", result.stderr)

    def test_a_method_that_belongs_to_another_type_fails(self):
        result = self.mutated("`Server::take_handover`", "`Server::persist_journal`")
        self.assertEqual(result.returncode, 1)
        self.assertIn("has `persist_journal`", result.stderr)

    def test_comments_and_strings_are_not_code(self):
        spec = importlib.util.spec_from_file_location("check_model_locations", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        code = module.strip_rust(
            '// fn gone_in_comment\n/* fn gone_in_block */ fn kept() { let _ = "fn gone_in_string"; }\n'
            "impl Holder { fn method(&self) {} }\n")
        index = module.Index(code)
        self.assertEqual(index.defined, {"kept", "method"})
        self.assertEqual(index.members["Holder"], {"method"})

    def test_a_table_whose_code_header_was_renamed_is_not_skipped(self):
        result = self.mutated("| Spec action | Code location |", "| Spec action | Implementation |", 1)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not checked", result.stderr)

    def with_exit_row(self, rewrite):
        """The real README with the `Workspace: Exit (cascade)` row rewritten."""
        lines = README.read_text().splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith("| Workspace: Exit (cascade)"))
        lines[index] = rewrite(lines[index].replace("`split.rs` `cancel`", "`split.rs` `canceldriftgpt`"))
        self.assertIn("canceldriftgpt", lines[index])
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "README.md"
            path.write_text("\n".join(lines) + "\n")
            return run(path)

    def test_a_row_with_compact_separators_is_still_checked(self):
        result = self.with_exit_row(lambda row: row.replace(" | ", "|"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("canceldriftgpt", result.stderr)

    def test_a_short_row_is_rejected_not_skipped(self):
        result = self.with_exit_row(lambda row: "| `split.rs` `canceldriftgpt` |")
        self.assertEqual(result.returncode, 1)
        self.assertIn("cells but the table header has", result.stderr)

    def test_an_indented_table_is_still_read(self):
        lines = README.read_text().splitlines()
        first = next(i for i, line in enumerate(lines) if line.startswith("| Spec action | Code location |"))
        end = next(i for i in range(first, len(lines)) if not lines[i].startswith("|"))
        for i in range(first, end):
            lines[i] = " " + lines[i]
        text = "\n".join(lines).replace("`split.rs` `cancel`", "`split.rs` `canceldriftgpt`") + "\n"
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "README.md"
            path.write_text(text)
            result = run(path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("canceldriftgpt", result.stderr)

    def test_an_escaped_pipe_stays_inside_its_cell(self):
        result = self.check_row("`split.rs` `cancel_lane_jobs` (`a\\|b`)")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_table_that_names_no_code_column_is_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "README.md"
            path.write_text("| Invariant | Control |\n|---|---|\n| `cancel_children_of` | `x_y` |\n")
            result = run(path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no code table found", result.stderr)


if __name__ == "__main__":
    unittest.main()
