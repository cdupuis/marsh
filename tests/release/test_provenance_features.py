"""The release provenance filter refuses every test-only feature, on any crate:
`test-breaks` and `test-support` (the stuck-engine harness of marsh-sbx and its
test-only helpers ship nowhere)."""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/provenance.py"
spec = importlib.util.spec_from_file_location("provenance", SCRIPT)
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


def verify(units):
    """`provenance.py verify` of one artifact built in a group with these units."""
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        artifact = directory / "marsh"
        artifact.write_bytes(b"binary")
        gid = provenance.group_id(units)
        manifest = {
            "version": provenance.VERSION,
            "groups": {gid: {"label": "", "command": "cargo build", "units": units}},
            "artifacts": {
                "marsh": {
                    "sha256": hashlib.sha256(b"binary").hexdigest(),
                    "group": gid,
                    "package": "marsh",
                    "bin": "marsh",
                }
            },
        }
        (directory / "provenance.json").write_text(json.dumps(manifest))
        return subprocess.run(
            [sys.executable, str(SCRIPT), "verify", "--manifest", str(directory / "provenance.json"), str(artifact)],
            capture_output=True,
            text=True,
        )


class ForbiddenFeatures(unittest.TestCase):
    def test_test_breaks_is_still_forbidden_in_both_spellings(self):
        for feature in ("test-breaks", "test_breaks"):
            self.assertEqual(provenance.forbidden_in({"marsh": [feature]}), [f"marsh/{feature}"])

    def test_test_support_is_forbidden_on_any_crate_in_both_spellings(self):
        for crate in ("marsh-sbx", "marsh-runtime", "marsh"):
            for feature in ("test-support", "test_support"):
                self.assertEqual(provenance.forbidden_in({crate: ["default", feature]}), [f"{crate}/{feature}"])

    def test_ordinary_features_are_not(self):
        self.assertEqual(provenance.forbidden_in({"marsh-sbx": ["default"], "marsh": []}), [])

    def test_a_receipt_with_test_support_refuses_to_package(self):
        result = verify({"marsh": [], "marsh-sbx": ["test-support"]})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("marsh-sbx/test-support", result.stderr)
        self.assertIn("refusing to package", result.stderr)

    def test_a_clean_receipt_packages(self):
        result = verify({"marsh": [], "marsh-sbx": []})
        self.assertEqual(result.returncode, 0, result.stderr)


CFG = '--cfg feature="test-support"'


class HandPassedCfg(unittest.TestCase):
    """`--cfg feature="test-support"` passed by hand leaves Cargo's feature list
    empty; the receipt records the build's rustc flags, and verify refuses them."""

    def test_the_cfg_spellings_are_found(self):
        for flags in (
            ["--cfg", 'feature="test-support"'],
            ['--cfg=feature="test_support"'],
            ["--cfg", "feature='test-support'"],
            ["--cfg", 'feature=\\"test-support\\"'],
            ["-Copt-level=3", "--cfg", 'feature="test-breaks"'],
        ):
            self.assertTrue(provenance.forbidden_cfgs(flags), flags)
        for flags in (["--cfg", "unix"], ["-C", "opt-level=3"], ["--cfg", 'feature="serde"'], []):
            self.assertEqual(provenance.forbidden_cfgs(flags), [], flags)

    def test_every_flag_input_of_the_build_is_recorded(self):
        cases = {
            "RUSTFLAGS": ({"RUSTFLAGS": CFG}, []),
            "CARGO_ENCODED_RUSTFLAGS": ({"CARGO_ENCODED_RUSTFLAGS": "--cfg\x1ffeature=\"test-support\""}, []),
            "CARGO_BUILD_RUSTFLAGS": ({"CARGO_BUILD_RUSTFLAGS": CFG}, []),
            "CARGO_TARGET_*_RUSTFLAGS": ({"CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS": CFG}, []),
            "--config": ({}, ["cargo", "build", "--config", 'build.rustflags=["--cfg", \'feature="test-support"\']']),
        }
        for name, (environment, command) in cases.items():
            flags = provenance.build_flags(command, environment, cwd=tempfile.gettempdir())
            self.assertTrue(provenance.forbidden_cfgs(flags), name)

    def test_a_cargo_config_file_is_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            (directory / ".cargo").mkdir()
            (directory / ".cargo/config.toml").write_text(
                '[build]\nrustflags = ["--cfg", "feature=\\"test-support\\""]\n'
            )
            flags = provenance.build_flags(["cargo", "build"], {}, cwd=str(directory))
            self.assertTrue(provenance.forbidden_cfgs(flags))

    def test_a_receipt_recording_the_cfg_refuses_to_package(self):
        result = verify({"marsh": [], provenance.FLAGS_UNIT: ["--cfg", 'feature="test-support"']})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("test-support", result.stderr)
        self.assertIn("refusing to package", result.stderr)

    def test_a_receipt_with_ordinary_flags_packages(self):
        self.assertEqual(verify({"marsh": [], provenance.FLAGS_UNIT: ["-C", "opt-level=3"]}).returncode, 0)

    @unittest.skipUnless(shutil.which("cargo"), "needs cargo")
    def test_a_real_wrapper_build_with_the_cfg_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            (directory / "src").mkdir()
            (directory / "Cargo.toml").write_text('[package]\nname = "probe"\nversion = "0.0.0"\nedition = "2021"\n\n[workspace]\n')
            (directory / "src/main.rs").write_text("fn main() {}\n")

            def build(rustflags):
                environment = {key: value for key, value in os.environ.items() if "RUSTFLAGS" not in key}
                environment["CARGO_TARGET_DIR"] = str(directory / "target")
                if rustflags:
                    environment["RUSTFLAGS"] = rustflags
                manifest = directory / "provenance.json"
                subprocess.run(
                    [sys.executable, str(SCRIPT), "build", "--manifest", str(manifest), "--reset", "--", "cargo", "build", "--release", "--offline", "--manifest-path", str(directory / "Cargo.toml")],
                    check=True, capture_output=True, text=True, env=environment, cwd=directory,
                )
                return subprocess.run(
                    [sys.executable, str(SCRIPT), "verify", "--manifest", str(manifest), str(directory / "target/release/probe")],
                    capture_output=True, text=True,
                )

            control = build(None)
            self.assertEqual(control.returncode, 0, control.stderr)
            refused = build(CFG)
            self.assertEqual(refused.returncode, 1, refused.stderr)
            self.assertIn("test-support", refused.stderr)


MARKER = "marsh-feature:test-support"
BACKSTOP = ROOT / "scripts/check-no-test-breaks.sh"


class HarnessMarker(unittest.TestCase):
    def check(self, content):
        with tempfile.TemporaryDirectory() as temporary:
            binary = pathlib.Path(temporary) / "marsh"
            binary.write_bytes(content)
            return subprocess.run(["sh", str(BACKSTOP), str(binary)], capture_output=True, text=True)

    def test_the_binary_backstop_refuses_the_harness_marker(self):
        refused = self.check(b"\x00\x00" + MARKER.encode() + b"\x00 some other text")
        self.assertEqual(refused.returncode, 1, refused.stderr)
        self.assertIn("test-support", refused.stderr)
        self.assertEqual(self.check(b"\x00 an ordinary binary \x00").returncode, 0)

    def test_the_harness_keeps_exactly_that_marker(self):
        source = (ROOT / "crates/marsh-sbx/src/stuck_engine.rs").read_text()
        self.assertIn(f'*b"{MARKER}"', source)
        self.assertIn(f"[u8; {len(MARKER)}]", source)


COMPILE_PROBE = ROOT / "target/release-guard-probe"


def pinned_toolchain_installed():
    """Whether `cargo` in this checkout runs the toolchain rust-toolchain.toml pins,
    decided without the network: under rustup, a missing pinned channel makes the
    proxy download it, which these probes must never trigger."""
    if not shutil.which("cargo"):
        return False
    if not shutil.which("rustup"):
        return True
    channel = re.search(r'channel\s*=\s*"([^"]+)"', (ROOT / "rust-toolchain.toml").read_text())
    if channel is None:
        return True
    listed = subprocess.run(["rustup", "toolchain", "list"], capture_output=True, text=True)
    return any(line.split()[0].startswith(channel.group(1)) for line in listed.stdout.splitlines() if line.strip())


# The Rust lanes of CI set this: there the probes must run, not be skipped. Where no
# pinned toolchain is installed (the tooling job has none), they skip with a message.
REQUIRED = os.environ.get("MARSH_REQUIRE_RUST_PROBES") == "1"


def dependencies_resolve_offline():
    """The probes build marsh-sbx offline: skip where the registry was never fetched
    (the tooling job has a cargo but no `cargo fetch`)."""
    environment = dict(os.environ, RUSTUP_AUTO_INSTALL="0")
    try:
        done = subprocess.run(
            ["cargo", "metadata", "--offline", "--locked", "--format-version", "1"],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


@unittest.skipUnless(
    REQUIRED or (pinned_toolchain_installed() and dependencies_resolve_offline()),
    "the pinned Rust toolchain or the fetched crate registry is missing; these probes run in the Rust lanes",
)
class CompileTimeRefusal(unittest.TestCase):
    """marsh-sbx refuses the harness at compile time under MARSH_RELEASE_PACKAGING=1,
    whether the feature comes from Cargo or from a hand-passed `--cfg`."""

    def check(self, extra, packaging=True, rustflags=None):
        environment = {key: value for key, value in os.environ.items() if "RUSTFLAGS" not in key and key != "MARSH_RELEASE_PACKAGING"}
        environment["RUSTUP_AUTO_INSTALL"] = "0"
        if packaging:
            environment["MARSH_RELEASE_PACKAGING"] = "1"
        if rustflags:
            environment["RUSTFLAGS"] = rustflags
        return subprocess.run(
            ["cargo", "check", "--offline", "--locked", "-p", "marsh-sbx", "--target-dir", str(COMPILE_PROBE), *extra],
            cwd=ROOT, env=environment, capture_output=True, text=True,
        )

    def test_the_cargo_feature_is_refused(self):
        result = self.check(["--features", "test-support"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release packaging (MARSH_RELEASE_PACKAGING=1) refuses it", result.stderr)

    def test_a_hand_passed_cfg_is_refused(self):
        result = self.check([], rustflags=CFG)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release packaging (MARSH_RELEASE_PACKAGING=1) refuses it", result.stderr)

    def test_an_ordinary_release_build_still_compiles(self):
        result = self.check([])
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
