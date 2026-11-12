#!/usr/bin/env python3
"""Scale the project-site thumbnails taken by the browser test down to their published size.

  tools/make_thumbs.py E2E_SHOTS_DIR docs/shots

The browser test (tools/e2e/e2e.cjs) saves one screen of each page at twice the resolution as
thumb-<lang>-<name>.png (2400 x 1800). Halving them with a Lanczos filter keeps small text sharp; shown at about
600 CSS px on a high-density screen they are close to one image pixel per screen pixel. Output:
docs/shots/<lang>/thumb/<name>.webp. Needs Pillow (development machine only; nothing here ships in the release).
"""
import os
import re
import sys

from PIL import Image

SIZE = (1200, 900)


def main(src, dst):
    n = 0
    for f in sorted(os.listdir(src)):
        m = re.fullmatch(r'thumb-(zh-TW|en|ja)-([a-z-]+)\.png', f)
        if not m:
            continue
        out = os.path.join(dst, m.group(1), 'thumb')
        os.makedirs(out, exist_ok=True)
        with Image.open(os.path.join(src, f)) as im:
            im = im.convert('RGB').resize(SIZE, Image.LANCZOS)
            im.save(os.path.join(out, m.group(2) + '.webp'), 'WEBP', quality=90, method=6)
        n += 1
    if not n:
        sys.exit('no thumb-*.png in ' + src)
    print('thumbnails: %d written' % n)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
