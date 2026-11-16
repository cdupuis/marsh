"""The prewarm `--load` runs of the acceptance harness get a cold-build budget (no VMs)."""
from __future__ import annotations

import pathlib
import subprocess
import sys
import unittest
from typing import Any, Callable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run  # noqa: E402


class _Captured(Exception):
    """Raised by the stub `mark` once the prewarm step has been handed over."""


class _Stop(Exception):
    """Raised by the stub `state_snapshot`: the loads are over, nothing else runs."""


def captured_prewarm(harness: Any) -> Callable[[], None]:
    """The real `prewarm` step, as `run_all` hands it to `mark`."""
    steps: dict[str, Callable[[], None]] = {}

    def mark(name: str, function: Callable[[], None], **_: object) -> None:
        steps[name] = function
        if name == "prewarm-ready-and-subsecond":
            raise _Captured

    harness.mark = mark
    try:
        harness.run_all()
    except _Captured:
        return steps["prewarm-ready-and-subsecond"]
    raise AssertionError("run_all never reached the prewarm step")


class PrewarmLoadTimeoutTests(unittest.TestCase):
    def test_the_budget_covers_a_cold_build_on_a_busy_machine(self) -> None:
        self.assertGreaterEqual(run.PREWARM_LOAD_TIMEOUT_S, 900)

    def test_both_loads_run_under_that_budget(self) -> None:
        harness = run.Harness.__new__(run.Harness)
        harness.marsh = "marsh"
        harness.project = pathlib.Path("project")
        calls: list[tuple[list[str], float]] = []

        def fake_run(argv: list[str], *, timeout: float = 30, **_: object) -> subprocess.CompletedProcess[bytes]:
            calls.append((argv, timeout))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        def stop(_: str) -> dict[str, Any]:
            raise _Stop

        prewarm = captured_prewarm(harness)
        harness.run = fake_run
        harness.state_snapshot = stop
        with self.assertRaises(_Stop):
            prewarm()
        self.assertEqual([argv[2] for argv, _ in calls], ["fixture", "all"])
        self.assertEqual([argv[:2] for argv, _ in calls], [["marsh", "--load"]] * 2)
        for argv, timeout in calls:
            self.assertEqual(timeout, run.PREWARM_LOAD_TIMEOUT_S, argv)
            self.assertGreaterEqual(timeout, 900, argv)


if __name__ == "__main__":
    unittest.main()
