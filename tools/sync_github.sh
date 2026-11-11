#!/bin/sh
# Copy exactly the publishable files (PUBLISH.txt) from the working directory into github/, the git
# repository, then run the privacy / release checks there. Nothing else ever reaches the repository.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DST="$ROOT/github"
[ -d "$DST/.git" ] || { echo "no git repository in $DST" >&2; exit 1; }
cd "$ROOT"
grep -v '^\s*#' PUBLISH.txt | sed 's/#.*//; s/[[:space:]]*$//' | grep -v '^$' > "$DST/.publish-list.tmp"
# remove published paths that no longer exist here, then copy the current ones
( cd "$DST" && git ls-files ) | while read -r f; do
    case "$f" in .gitignore|.gitattributes) continue ;; esac
    [ -e "$ROOT/$f" ] || rm -f "$DST/$f"
done
while read -r p; do
    if [ -d "$ROOT/$p" ]; then
        mkdir -p "$DST/$p"
        rsync -a --delete --exclude '__pycache__/' --exclude '*.pyc' --exclude 'node_modules/' "$ROOT/$p/" "$DST/$p/"
    elif [ -e "$ROOT/$p" ]; then
        mkdir -p "$DST/$(dirname "$p")"
        cp -p "$ROOT/$p" "$DST/$p"
    fi
done < "$DST/.publish-list.tmp"
rm -f "$DST/.publish-list.tmp"
python3 "$DST/tools/preflight.py" --no-tests
