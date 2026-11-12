#!/usr/bin/env python3
"""CycloneDX 1.5 SBOM of what a jt-waf-mgr release ships.

The backend uses the Python standard library only; the UI bundle (jtwafmgr/static) contains Vue and
Vue Router. Versions are read from the node_modules the UI was built with.
  tools/make_sbom.py VERSION > sbom.cdx.json
"""
import glob
import json
import os
import sys
import uuid
import datetime

NM = os.environ.get('JTWAF_NODE_MODULES', '/opt/jt-ipam/frontend/node_modules')
BUNDLED = ['vue', '@vue/runtime-dom', '@vue/runtime-core', '@vue/reactivity', '@vue/shared', 'vue-router', '@iconoir/vue']


def _read(p):
    with open(p) as fh:
        return json.load(fh)


def pkg(name, prefer=None):
    """package.json of a bundled package: top level, or in the pnpm store (preferring the version
    that matches Vue's for the @vue/* parts)."""
    top = os.path.join(NM, name, 'package.json')
    if os.path.exists(top):
        return _read(top)
    found = [_read(p) for p in glob.glob(os.path.join(NM, '.pnpm', '*', 'node_modules', name, 'package.json'))]
    for d in found:
        if d.get('version') == prefer:
            return d
    return found[0] if found else None


def main():
    version = sys.argv[1]
    comps = []
    vue_version = (pkg('vue') or {}).get('version')
    for name in BUNDLED:
        d = pkg(name, vue_version)
        if not d:
            continue
        purl = 'pkg:npm/%s@%s' % (name.replace('@', '%40'), d['version'])
        comps.append({'type': 'library', 'name': name, 'version': d['version'], 'purl': purl, 'bom-ref': purl,
                      'licenses': [{'license': {'id': d.get('license', 'NOASSERTION')}}],
                      'properties': [{'name': 'jt-waf-mgr:location', 'value': 'jtwafmgr/static (UI bundle)'}]})
    py = '%d.%d' % sys.version_info[:2]
    bom = {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'serialNumber': 'urn:uuid:%s' % uuid.uuid4(), 'version': 1,
        'metadata': {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            'component': {'type': 'application', 'name': 'jt-waf-mgr', 'version': version,
                          'licenses': [{'license': {'id': 'AGPL-3.0-or-later'}}],
                          'bom-ref': 'jt-waf-mgr@%s' % version},
            'properties': [{'name': 'jt-waf-mgr:python', 'value': 'standard library only (built and tested with %s; '
                                                                   'requires 3.11+)' % py}]},
        'components': comps,
        'dependencies': [{'ref': 'jt-waf-mgr@%s' % version, 'dependsOn': [c['bom-ref'] for c in comps]}],
    }
    json.dump(bom, sys.stdout, indent=1)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
