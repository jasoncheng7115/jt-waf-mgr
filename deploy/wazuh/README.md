# Wazuh rules for jt-waf-mgr (draft)

`jt-waf-mgr_decoders.xml` and `jt-waf-mgr_rules.xml` turn the audit lines jt-waf-mgr sends to syslog into
Wazuh alerts. They are meant to become a rule pack (rule range 133560-133589) and still need a run on a
test manager before production.

What they alert on:

- integrity failures (`integrity.*_failed`: audit chain, program files, database), level 12; recovery level 3;
- the integrity monitor itself failing, level 8;
- nginx / ModSecurity / CRS files changed outside the change workflow, level 10;
- failed logins (level 5), 5 from one address in 5 minutes (level 10), account locked (level 10);
- TOTP turned off, passwords reset, accounts and API tokens created or changed, settings changed (level 7-10);
- WAF changes applied or rolled back (level 5), an apply that failed and was restored (level 10);
- refused actions (`*_denied`, level 8); audit purge and failed backups (level 7);
- any other record marked `"severity": "crit"`, level 12.

The chain anchors (`"kind": "audit_anchor"`, every 5 minutes) are kept at level 0. They are the heartbeat:
if they stop, either jt-waf-mgr or the syslog path is down.

Requirements on the jt-waf-mgr host: `[syslog] enabled = true` (the default) and an agent that reads
`/var/log/syslog` or journald.

The reviewed and sandbox-tested version of these rules ships in the jt-modsecurity rule pack (jt-wazuh-mgr); this
directory keeps the draft that matches each jt-waf-mgr release. Changes from that review: refusals match `[._]denied$`
(`token.denied` uses a dot), the login rules carry only the cross-pack groups (not Wazuh's `authentication_*`, whose
built-in night-time rules would raise every login), and sibling decoders copy `src_ip` / `actor` into `srcip` / `user`.

If the Wazuh agent on the jt-waf-mgr host reads both `/var/log/syslog` and `/var/log/messages`, every line arrives twice
and the frequency rules (5 failed logins in 5 minutes) fire at half the count. Send jt-waf-mgr's records to a facility
that only one of those files gets, or have the agent read just one of them.
