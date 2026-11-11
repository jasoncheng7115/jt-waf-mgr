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
        from .compliance import Monitor
        self.monitor = Monitor(self)
        if start_collector:
            self.start_collector()

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
        th = threading.Thread(target=self.tailer.run, name='collector', daemon=True)
        th.start()
        self._threads.append(th)
        hk = threading.Thread(target=self._housekeeping, name='housekeeping', daemon=True)
        hk.start()
        self._threads.append(hk)

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
