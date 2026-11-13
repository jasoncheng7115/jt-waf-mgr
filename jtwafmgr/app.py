"""Wires configuration, storage, collector and web layer together."""
import threading
import time

from .audit import Audit
from .auth import Auth
from .collector.auditlog import Tailer
from .db import Database
from .site import Site
from .web import api
from .web.server import Router


class App:
    def __init__(self, cfg, start_collector=False):
        self.cfg = cfg
        self.db = Database(cfg['paths']['db'])
        from .uisettings import apply as _apply_ui_settings
        _apply_ui_settings(cfg, self.db)       # settings changed in the web interface override the file
        self.audit = Audit(self.db, cfg)
        self.auth = Auth(self.db, cfg, self.audit)
        self.site = Site(cfg)
        from .geoip import GeoIP
        self.geoip = GeoIP(cfg)
        api.GEO = self.geoip.lookup
        self.router = Router()
        api.register(self.router)
        self.tailer = None
        self._threads = []
        from .changes import Workflow
        from .evidence import Evidence
        from .sandbox import Sandbox
        self.workflow = Workflow(self)
        self.workflow.evidence = Evidence(cfg, self.db)
        self.workflow.sandbox = Sandbox(cfg, self.site)
        from .blocks import Blocks
        self.blocks = Blocks(self)
        from .compliance import Monitor
        self.monitor = Monitor(self)
        self._note_version()
        if start_collector:
            self.start_collector()

    def _note_version(self):
        """One audit row whenever the program version differs from the last run (upgrade or rollback)."""
        from . import __version__
        try:
            prev = self.db.get_meta('program_version')
            if prev != __version__:
                self.db.set_meta('program_version', __version__)
                if not prev and self.db.one('SELECT 1 FROM audit LIMIT 1'):
                    prev = 'before 0.3.1'          # a database from a version that did not note its version
                if prev:
                    self.audit.log('system.version_changed', 'system', 'system', None, 'ok',
                                   severity='crit' if prev[0].isdigit() and _vkey(__version__) < _vkey(prev) else None,
                                   previous=prev, current=__version__)
        except Exception:      # never keep the service from starting over a note
            pass

    def start_collector(self):
        wf = threading.Thread(target=self.workflow.run, name='workflow', daemon=True)
        wf.start()
        self._threads.append(wf)
        mon = threading.Thread(target=self.monitor.run, name='monitor', daemon=True)
        mon.start()
        self._threads.append(mon)
        if not self.cfg['collector']['enabled']:
            return
        self.tailer = Tailer(self.cfg, self.db)
        self.tailer.store.on_new = self.audit.events
        th = threading.Thread(target=self.tailer.run, name='collector', daemon=True)
        th.start()
        self._threads.append(th)
        hk = threading.Thread(target=self._housekeeping, name='housekeeping', daemon=True)
        hk.start()
        self._threads.append(hk)
        bt = threading.Thread(target=self.blocks.run, args=(self.tailer._stop,), name='blocks', daemon=True)
        bt.start()
        self._threads.append(bt)
        from . import traffic
        tr = threading.Thread(target=traffic.run, args=(self, self.tailer._stop), name='traffic', daemon=True)
        tr.start()
        self._threads.append(tr)

    def _housekeeping(self):
        stop = self.tailer._stop
        while not stop.wait(600):
            try:
                self.auth.purge_sessions()
                last = self.workflow.managed.setting('samples.collected_at', 0)
                if time.time() - last > 86400:
                    self.workflow.managed.set_setting('samples.collected_at', time.time())
                    self.workflow.evidence.collect_samples()
                days = self.cfg['retention']['audit_days']
                if days:
                    n = self.audit.chain.purge_before(time.time() - 86400 * days)
                    if n:
                        self.audit.log('audit.purged', 'system', 'system', None, 'ok', rows=n, older_than_days=days)
            except Exception:
                pass

    def stop(self):
        self.monitor.stop()
        self.workflow.stop()
        if self.tailer:
            self.tailer.stop()


def _vkey(v):
    out = []
    for p in str(v).split('.'):
        n = ''.join(ch for ch in p if ch.isdigit())
        out.append(int(n) if n else 0)
    return out
