"""Who can reach a server block (nginxconf._reach): from nginx's own source checks for the whole block, resolving geo
and map variables -- not from DNS. Synthetic configuration only."""
import os
import unittest

from jtwafmgr.nginxconf import NginxConfig
from tests.helpers import TempEnv

CONF = """
events {}
http {
    geo $lan { default 0; 10.0.0.0/8 1; 192.168.0.0/16 1; }
    geo $tw { default 0; include %(dir)s/tw.conf; 192.168.0.0/16 1; }
    geo $one { default 0; 198.51.100.7 1; }
    geo $wide { default 1; 203.0.113.0/24 0; }
    map $tw $tw_ok { default 0; 1 1; }
    map "$lan:$http_x" $odd { default 0; "~^1:" 1; }
    server { listen 443; server_name lan.example.com; if ($lan = 0) { return 444; } location / { proxy_pass http://192.0.2.1; } }
    server { listen 443; server_name tw.example.com; if ($tw = 0) { return 403; } root /srv; }
    server { listen 443; server_name map.example.com; if ($tw_ok = 0) { return 403; } root /srv; }
    server { listen 443; server_name one.example.com; if ($one != 1) { return 403; } root /srv; }
    server { listen 443; server_name wide.example.com; if ($wide = 0) { return 403; } root /srv; }
    server { listen 443; server_name odd.example.com; if ($odd = 0) { return 403; } root /srv; }
    server { listen 443; server_name acl.example.com; allow 10.0.0.0/8; allow 192.168.77.0/24; deny all; root /srv; }
    server { listen 443; server_name both.example.com; if ($tw = 0) { return 403; } if ($lan = 0) { return 444; } root /srv; }
    server { listen 443; server_name loc.example.com; location /admin { if ($lan = 0) { return 403; } } root /srv; }
    server { listen 443; server_name open.example.com; root /srv; }
    server { listen 80; server_name open.example.com; return 301 https://$host$request_uri; }
    server { listen 80; server_name lan.example.com; if ($lan = 0) { return 444; } return 301 https://$host$request_uri; }
}
"""


class TestReach(unittest.TestCase):
    def test_blocks(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        with open(os.path.join(env.dir, 'tw.conf'), 'w') as fh:            # a country list: many public networks
            fh.write(''.join('198.18.%d.0/24 1;\n' % i for i in range(60)))
        path = os.path.join(env.dir, 'nginx.conf')
        with open(path, 'w') as fh:
            fh.write(CONF % {'dir': env.dir})
        got = {(s['server_names'][0], s['listen'][0]): (s['reach'], s['redirect_only']) for s in NginxConfig(path).servers()}
        self.assertEqual(got[('lan.example.com', '443')], ('internal', False))
        self.assertEqual(got[('tw.example.com', '443')], ('country', False))
        self.assertEqual(got[('map.example.com', '443')], ('country', False))       # a map of a geo variable
        self.assertEqual(got[('one.example.com', '443')], ('limited', False))        # "!= 1"
        self.assertEqual(got[('wide.example.com', '443')], ('restricted', False))    # default passes: not closed
        self.assertEqual(got[('odd.example.com', '443')], ('restricted', False))     # a regex map: not understood
        self.assertEqual(got[('acl.example.com', '443')], ('internal', False))
        self.assertEqual(got[('both.example.com', '443')], ('internal', False))      # the narrowest check decides
        self.assertEqual(got[('loc.example.com', '443')], ('open', False))           # a location check is not the block
        self.assertEqual(got[('open.example.com', '443')], ('open', False))
        self.assertEqual(got[('open.example.com', '80')], ('open', True))            # only redirects
        self.assertEqual(got[('lan.example.com', '80')], ('internal', True))


if __name__ == '__main__':
    unittest.main()
