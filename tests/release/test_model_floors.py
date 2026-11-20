"""docs/model/check.sh fails a positive config below its state floor, and bad floor files."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

MODEL = pathlib.Path(__file__).resolve().parents[2] / "docs/model"

# A TLC that prints what FAKE_STATES says it found.
FAKE_JAVA = """#!/bin/sh
echo "Model checking completed. No error has been found."
echo "10 states generated, ${FAKE_STATES} distinct states found, 0 states left on queue."
"""


class StateFloors(unittest.TestCase):
    def setUp(self):
        self.directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.model = self.directory / "model"
        self.model.mkdir()
        for name in ("check.sh", "Pins.tla", "Pins.cfg", "Ownership.tla", "Ownership.cfg"):
            shutil.copy(MODEL / name, self.model / name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        (self.bin / "java").write_text(FAKE_JAVA)
        (self.bin / "java").chmod(0o755)
        (self.directory / "tla2tools.jar").write_text("jar")

    def run_check(self, floors, states="1,124", cache=False, configs=("Pins.cfg",)):
        (self.model / "state-floors.txt").write_text(floors)
        environment = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", TLC_RUNNER="java",
                           TLA2TOOLS_JAR=str(self.directory / "tla2tools.jar"), FAKE_STATES=states)
        environment.pop("TLC_CACHE", None)
        if cache:
            environment["TLC_CACHE"] = str(self.directory / "cache")
        return subprocess.run(["bash", str(self.model / "check.sh"), "--cores", "1", "--workers", "1", *configs],
                              capture_output=True, text=True, timeout=60, env=environment, cwd=self.model)

    def test_a_count_at_or_above_the_floor_passes(self):
        result = self.run_check("Pins.cfg 560\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.run_check("Pins.cfg 1124\n").returncode, 0)

    def test_a_count_below_the_floor_fails(self):
        result = self.run_check("Pins.cfg 560\n", states="12")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("below the floor 560", result.stdout)

    def test_a_config_with_no_floor_fails(self):
        result = self.run_check("# nothing\n")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("missing, repeated or not a number", result.stdout)

    def test_a_missing_state_count_fails(self):
        result = self.run_check("Pins.cfg 560\n", states="")
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_a_bad_floor_file_is_refused_before_any_run(self):
        # Each case with and without a final newline: `read` fails on an unterminated
        # last line, which must still be checked.
        for floors in ("Pins.cfg 51\nPins.cfg 999999",         # twice
                       "Pins.cfg 99999999999999999999",          # too many digits
                       "Pins.cfg 1000000000000000",              # 16 digits
                       "Pins.cfg 0", "Pins.cfg 05", "Pins.cfg lots", "Pins.cfg", "Pins.cfg -5",
                       "Pins.cfg 560 extra", "Gone.cfg 5\nPins.cfg 560"):
            for ending in ("\n", ""):
                with self.subTest(floors=floors, final_newline=bool(ending)):
                    result = self.run_check(floors + ending)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_a_good_floor_file_passes_with_or_without_a_final_newline(self):
        for ending in ("\n", ""):
            result = self.run_check("# floors\nPins.cfg 560" + ending)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_state_count_that_is_not_a_plain_number_fails(self):
        for states in ("-1124", "1124x", "1000000000000000"):
            with self.subTest(states=states):
                result = self.run_check("Pins.cfg 560\n", states=states)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_a_module_glob_selects_its_configs_not_the_module(self):
        shutil.copy(MODEL / "Pins_leak.cfg", self.model / "Pins_leak.cfg")
        result = self.run_check("Pins.cfg 560\n", configs=("--list", "Pins*"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        listed = [line.split()[0] for line in result.stdout.splitlines() if "workers=" in line]
        self.assertEqual(sorted(listed), ["Pins.cfg", "Pins_leak.cfg"], result.stdout)

    def test_the_cache_is_keyed_on_the_configs_own_floor(self):
        both = ("Ownership.cfg", "Pins.cfg")
        floors = "Ownership.cfg 50\nPins.cfg 560\n"
        self.assertEqual(self.run_check(floors, cache=True, configs=both).returncode, 0)
        again = self.run_check(floors.replace("Ownership.cfg 50", "Ownership.cfg 60"), cache=True, configs=both)
        self.assertEqual(again.returncode, 0, again.stdout)
        self.assertEqual(again.stdout.count("cached"), 1, again.stdout)  # only Pins came from the cache

    def test_a_raised_floor_is_not_answered_from_the_cache(self):
        first = self.run_check("Pins.cfg 560\n", cache=True)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(self.run_check("Pins.cfg 560\n", cache=True).stdout.count("cached"), 1)
        raised = self.run_check("Pins.cfg 5600\n", cache=True)
        self.assertEqual(raised.returncode, 1, raised.stdout)


if __name__ == "__main__":
    unittest.main()
