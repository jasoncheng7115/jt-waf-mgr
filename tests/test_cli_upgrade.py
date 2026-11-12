"""The commands the upgrade relies on: config-check, migrate, doctor, and the version-change audit row."""
import contextlib
import io
import json
import os
import unittest

from jtwafmgr import cli
from jtwafmgr.app import App
from tests.helpers import TempEnv


class TestUpgradeCommands(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.conf = os.path.join(self.env.dir, 'config.toml')
        with open(self.conf, 'w') as fh:
            fh.write('[paths]\ndb = "%s"\naudit_log = "%s"\nnginx_conf = "%s"\n[syslog]\nenabled = false\n'
                     '[integrity]\nanchor_file = "%s"\n[backup]\ndir = "%s"\n[managed]\napply_state = "%s"\n'
                     % (self.env.cfg['paths']['db'], self.env.audit_log, self.env.cfg['paths']['nginx_conf'],
                        os.path.join(self.env.dir, 'a.jsonl'), os.path.join(self.env.dir, 'b'),
                        os.path.join(self.env.dir, 'st')))

    def tearDown(self):
        self.env.cleanup()

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(['--config', self.conf] + list(args))
        return rc, out.getvalue()

    def test_config_check_and_migrate(self):
        rc, out = self.run_cli('config-check')
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out)['ok'])
        rc, out = self.run_cli('migrate')
        d = json.loads(out)
        self.assertEqual((rc, d['schema_before'], d['ok']), (0, None, True))
        rc, out = self.run_cli('migrate')
        self.assertEqual(json.loads(out)['schema_before'], json.loads(out)['schema_after'])

    def test_bad_config_is_refused(self):
        with open(self.conf, 'a') as fh:
            fh.write('[compliance]\nlevel = "extreme"\n')
        rc, _ = self.run_cli('config-check')
        self.assertEqual(rc, 2)

    def test_doctor_runs(self):
        rc, out = self.run_cli('doctor')
        self.assertIn('overall', out)

    def test_version_change_is_audited(self):
        app = App(self.env.cfg)
        app.db.set_meta('program_version', '0.0.1')
        App(self.env.cfg)
        rows = \
            app.db.q("SELECT details FROM audit WHERE action='system.version_changed'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['details'])['previous'], '0.0.1')


if __name__ == '__main__':
    unittest.main()
