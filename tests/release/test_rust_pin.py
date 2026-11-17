#!/usr/bin/env python3
"""The Rust toolchain: one pin, and every copy of it agrees.

`rust-toolchain.toml` names the release (`X.Y.Z`). The provenance gate
(scripts/build-candidate.py, tests/acceptance/provenance.py) rejects any other
compiler, so a copy left on the old release breaks builds. The container copies
name `rust:X.Y-bookworm@sha256:...`; Renovate moves those digests, never the
release (.github/renovate.json5), so a release bump is by hand and this test
lists every place it must land.
"""
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
IMAGE = re.compile(r"rust:(\d+\.\d+)-bookworm@(sha256:[0-9a-f]{64})")
# Each copy of the full release X.Y.Z, as (file, pattern with one group): the
# executable ones, and the prose that tells a contributor which one to install.
RELEASES = (
    ("scripts/build-candidate.py", r'"--toolchain", default="([^"]+)"'),
    ("packaging/linux-arm64/Dockerfile", r"rustup target add --toolchain (\S+)"),
    ("packaging/shell/Dockerfile", r"RUSTUP_TOOLCHAIN=(\S+)"),
    ("packaging/shell/Dockerfile", r"rustup (?:component|target) add --toolchain (\S+)"),
    ("CONTRIBUTING.md", r"rustup toolchain install (\S+) --profile"),
    ("CONTRIBUTING.md", r"Rust (\d+\.\d+\.\d+) \(`rust-toolchain\.toml` picks"),
    ("CONTRIBUTING.md", r"(?m)^(\d+\.\d+\.\d+), `cargo-nextest`"),
    ("docs/design/bash-compatibility.md", r"Prerequisites: Rust (\S+),"),
    (".github/workflows/ci.yml", r"rustup toolchain install (\S+) --profile"),
    (".github/workflows/release.yml", r"rustup toolchain install (\S+) --profile"),
    (".github/workflows/stress.yml", r"rustup toolchain install (\S+) --profile"),
)
# Each copy of the minor X.Y, the same way.
MINORS = (
    ("Cargo.toml", r'(?m)^rust-version = "([^"]+)"'),
    ("docs/install.md", r"Rust (\d+\.\d+),"),
    ("packaging/linux-arm64/README.md", r"`rust:(\d+\.\d+)-bookworm`"),
    ("packaging/shell/Dockerfile", r"pinned Rust (\d+\.\d+) toolchain"),
)
# Files naming the pinned image; each must agree on one tag and one digest.
IMAGES = (
    "Makefile",
    "scripts/build-candidate.py",
    "tests/acceptance/provenance.py",
    "tests/acceptance/fixture/fixture.dockerfile",
    "packaging/linux-arm64/Dockerfile",
    "packaging/shell/Dockerfile",
    "crates/marsh-services/e3/build-linux.sh",
    "crates/marsh-services/e3/clippy-linux.sh",
    "crates/marsh-services/e3/test-linux.sh",
)


def read(path):
    return (ROOT / path).read_text()


def release():
    return re.search(r'channel\s*=\s*"(\d+\.\d+\.\d+)"', read("rust-toolchain.toml")).group(1)


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [name for name in out.decode().split("\0") if name]


class RustPinTests(unittest.TestCase):
    def test_every_release_copy_matches_the_channel(self):
        want = release()
        for path, pattern in RELEASES:
            found = re.findall(pattern, read(path))
            self.assertTrue(found, f"{path}: no copy of the release found by {pattern}")
            self.assertEqual(set(found), {want}, f"{path} must pin Rust {want}")

    def test_every_minor_copy_matches_the_channel(self):
        want = ".".join(release().split(".")[:2])
        for path, pattern in MINORS:
            found = re.findall(pattern, read(path))
            self.assertTrue(found, f"{path}: no copy of the minor found by {pattern}")
            self.assertEqual(set(found), {want}, f"{path} must name Rust {want}")

    def test_no_unlisted_file_pins_the_toolchain(self):
        # The 1.99.1 move missed stress.yml and the e3 scripts: a new site must be listed.
        known = {path for path, _ in RELEASES} | set(IMAGES)
        sites = re.compile(r"rustup toolchain install \d|RUSTUP_TOOLCHAIN=\d|toolchain \d+\.\d+\.\d|rust:\d+\.\d+-bookworm@")
        for path in tracked():
            if path in known or path.startswith(("vendor/", "evals/", "docs/plan/", "packaging/dhi-notices/")):
                continue
            if path == "tests/release/test_rust_pin.py" or not (ROOT / path).is_file():
                continue
            try:
                text = read(path)
            except UnicodeDecodeError:
                continue
            self.assertIsNone(sites.search(text), f"{path} pins the Rust toolchain: list it in test_rust_pin.py")

    def test_every_image_site_agrees_on_tag_and_digest(self):
        minor = ".".join(release().split(".")[:2])
        digests = set()
        for path in IMAGES:
            found = IMAGE.findall(read(path))
            self.assertTrue(found, f"{path}: no pinned rust image found")
            for tag, digest in found:
                self.assertEqual(tag, minor, f"{path} must use rust:{minor}-bookworm")
                digests.add(digest)
        self.assertEqual(len(digests), 1, f"image sites disagree on the digest: {sorted(digests)}")


if __name__ == "__main__":
    unittest.main()
