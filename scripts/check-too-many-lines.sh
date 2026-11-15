#!/bin/sh
# Ratchet on #[allow(clippy::too_many_lines)] (and #[expect], and entries in a
# longer allow list) in the workspace crates. New code must split the function
# instead of adding an allow; the count may only go down. The budget lives in
# scripts/too-many-lines.budget: when you remove allows, lower it in the same
# change. vendor/ is excluded: it is upstream Brush plus patches.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
budget=$(tr -d '[:space:]' <"$here/too-many-lines.budget")
case "$budget" in
'' | *[!0-9]*) echo "check-too-many-lines: $here/too-many-lines.budget must hold one number" >&2; exit 2 ;;
esac

count=$(git -C "$root" grep -h 'clippy::too_many_lines' -- 'crates/*.rs' | grep -vcE '^[[:space:]]*//' || true)
if [ "$count" -gt "$budget" ]; then
	echo "check-too-many-lines: $count allows of clippy::too_many_lines, budget $budget." >&2
	echo "Split the long function instead of allowing the lint. List them with:" >&2
	echo "  git grep -n 'clippy::too_many_lines' -- 'crates/*.rs'" >&2
	exit 1
fi
if [ "$count" -lt "$budget" ]; then
	echo "check-too-many-lines: $count allows, budget $budget: lower scripts/too-many-lines.budget to $count"
else
	echo "check-too-many-lines: ok ($count allows)"
fi
