"""The prewarm `--load` runs of the acceptance harness get a cold-build budget (no VMs)."""
from __future__ import annotations

import ast
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run  # noqa: E402


def prewarm_load_timeouts() -> list[ast.expr]:
    """The `timeout=` argument of every `self.run(...)` call in `prewarm()`."""
    tree = ast.parse(pathlib.Path(run.__file__).read_text())
    prewarm = [
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "prewarm"
    ]
    assert len(prewarm) == 1, "expected exactly one prewarm() in run.py"
    timeouts = []
    for call in ast.walk(prewarm[0]):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "run":
            timeouts += [keyword.value for keyword in call.keywords if keyword.arg == "timeout"]
    return timeouts


class PrewarmLoadTimeoutTests(unittest.TestCase):
    def test_the_budget_covers_a_cold_build_on_a_busy_machine(self) -> None:
        self.assertGreaterEqual(run.PREWARM_LOAD_TIMEOUT_S, 900)

    def test_prewarm_runs_the_load_under_that_budget(self) -> None:
        timeouts = prewarm_load_timeouts()
        self.assertEqual(len(timeouts), 1, "prewarm() runs `--load fixture` and `--load all` from one call")
        self.assertIsInstance(timeouts[0], ast.Name)
        self.assertEqual(timeouts[0].id, "PREWARM_LOAD_TIMEOUT_S")


if __name__ == "__main__":
    unittest.main()
