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
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
IMAGE = re.compile(r"rust:(\d+\.\d+)-bookworm@(sha256:[0-9a-f]{64})")
# Each copy of the full release X.Y.Z, as (file, pattern with one group).
RELEASES = {
    "scripts/build-candidate.py": r'"--toolchain", default="([^"]+)"',
    "packaging/linux-arm64/Dockerfile": r"rustup target add --toolchain (\S+)",
    "packaging/shell/Dockerfile": r"RUSTUP_TOOLCHAIN=(\S+)",
    "CONTRIBUTING.md": r"rustup toolchain install (\S+) --profile",
    "docs/design/bash-compatibility.md": r"Prerequisites: Rust (\S+),",
    ".github/workflows/ci.yml": r"rustup toolchain install (\S+) --profile",
    ".github/workflows/release.yml": r"rustup toolchain install (\S+) --profile",
    ".github/workflows/stress.yml": r"rustup toolchain install (\S+) --profile",
}
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


class RustPinTests(unittest.TestCase):
    def test_every_release_copy_matches_the_channel(self):
        want = release()
        for path, pattern in RELEASES.items():
            found = re.findall(pattern, read(path))
            self.assertTrue(found, f"{path}: no copy of the release found")
            self.assertEqual(set(found), {want}, f"{path} must pin Rust {want}")
        found = re.findall(r"rustup (?:component|target) add --toolchain (\S+)", read("packaging/shell/Dockerfile"))
        self.assertEqual(set(found), {want}, "packaging/shell/Dockerfile must pin Rust " + want)

    def test_minor_copies_match_the_channel(self):
        minor = ".".join(release().split(".")[:2])
        self.assertEqual(re.search(r'(?m)^rust-version = "([^"]+)"', read("Cargo.toml")).group(1), minor)
        for path in ("docs/install.md",):
            self.assertIn(f"Rust {minor},", read(path), f"{path} must name Rust {minor}")
        self.assertIn(f"`rust:{minor}-bookworm`", read("packaging/linux-arm64/README.md"))

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
