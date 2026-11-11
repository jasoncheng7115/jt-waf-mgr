#!/bin/sh
# Build the offline release tarball: dist/jt-waf-mgr-<version>.tar.gz (+ .sha256, + .sig).
# Contains only what the target host needs, an SBOM, and release/MANIFEST.sha256 (SHA-256 of every
# file) signed with the release key; runs preflight on the result.
#   JTWAF_SIGNING_KEY  private key (default: the internal directory; never published)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
KEY=${JTWAF_SIGNING_KEY:-/opt/jt-waf-mgr-internal/signing/release-key.pem}
[ -r "$KEY" ] || { echo "signing key $KEY not readable" >&2; exit 1; }
# the public key in deploy/ must belong to the signing key
[ "$(openssl pkey -in "$KEY" -pubout)" = "$(cat deploy/release-key.pem)" ] \
    || { echo "deploy/release-key.pem does not match $KEY" >&2; exit 1; }
V=$(python3 -c 'import jtwafmgr; print(jtwafmgr.__version__)')
NAME="jt-waf-mgr-$V"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/$NAME"
mkdir -p "$D/docs" "$D/release" dist
cp -R jtwafmgr deploy "$D/"
cp install.sh uninstall.sh LICENSE README.md CHANGELOG.md SECURITY.md "$D/"
cp docs/COMPLIANCE.md docs/COMPLIANCE.zh-TW.md "$D/docs/"
find "$D" \( -name '__pycache__' -o -name '*.pyc' \) -prune -exec rm -rf {} +
chmod 755 "$D/install.sh" "$D/uninstall.sh" "$D/deploy/jt-waf-mgr.sh"
python3 tools/make_sbom.py "$V" > "$D/sbom.cdx.json"
# manifest: every file except release/ itself, sha256sum format (sha256sum -c works on it)
( cd "$D" && find . -type f ! -path './release/*' | sed 's|^\./||' | LC_ALL=C sort | xargs -d '\n' sha256sum ) \
    > "$D/release/MANIFEST.sha256"
openssl dgst -sha256 -sign "$KEY" -out "$D/release/MANIFEST.sha256.sig" "$D/release/MANIFEST.sha256"
python3 -I -B -c '
import sys
sys.path.insert(0, sys.argv[1])
from jtwafmgr import integrity
r = integrity.verify_release(sys.argv[1], open(sys.argv[2]).read())
assert r["ok"], r
print("manifest: %d files, signature ok, key %s" % (r["checked"], r["key_fingerprint"]))
' "$D" deploy/release-key.pem
tar -C "$STAGE" --owner=0 --group=0 --sort=name -czf "dist/$NAME.tar.gz" "$NAME"
( cd dist && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )
openssl dgst -sha256 -sign "$KEY" -out "dist/$NAME.tar.gz.sig" "dist/$NAME.tar.gz"
python3 tools/preflight.py --tar "dist/$NAME.tar.gz" "$@"
ls -l "dist/$NAME.tar.gz"
cat "dist/$NAME.tar.gz.sha256"
echo "verify: openssl dgst -sha256 -verify deploy/release-key.pem -signature dist/$NAME.tar.gz.sig dist/$NAME.tar.gz"
