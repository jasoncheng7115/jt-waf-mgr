# Changelog

**English** · [繁體中文](CHANGELOG_zh-TW.md) · [日本語](CHANGELOG_ja.md)

## 0.5.54 (2026-11-29)

- With the model set to "default" in Settings, the second-tier threat intelligence stopped running (the system check said the LLM was not configured) while its connection test passed: the test used the first model the server lists, the scheduled run treated the empty model as not configured. The first-tier event analysis, the single-event AI analysis and the threat intelligence now all do what the test does and use the server's first listed model, and the run record names the model used. At OpenAI itself a model is still required.

## 0.5.53 (2026-11-28)

- While an LLM connection test runs, the page now shows a spinner and how long it has waited; after 20 seconds it explains that the first time, the server may first load the model into memory (Ollama took about 3 minutes for a 28 GB model, which looked like a hang). The same for both tiers and the search tool test.

## 0.5.52 (2026-11-28)

- When the saved model is not on the LLM server (the server changed models, or a different server was set), the model list after a failed connection test still held only the old model, so another could not be picked: from 0.5.48 the server sent its model list, but the page dropped every failed result. Both tiers now list the server's models, and the message says in plain words what to do.
- Picking another model and pressing the connection test now saves it first (the test used the old model before).

## 0.5.51 (2026-11-28)

- The LibreNMS protection set could not be proposed: the sandbox wants, for each rule, an attack test sent from outside, and the rules that apply to every source had theirs sent from inside only. The attack tests are now sent from outside; ordinary requests to administration pages and the API stay inside. A test now checks this for every set.

## 0.5.50 (2026-11-28)

- LibreNMS protection set (12 rules, from the LibreNMS security advisories, NVD and the routes in its source; measured against seven weeks of real LibreNMS requests, none matched):
  - From outside: administration pages (settings, users and roles, API tokens, plugin settings, validation and the installer, pollers, alert transports and templates, alert rule editing, stored secrets, adding, editing and deleting devices, network tools, debug captures). Dashboards, graphs, device pages, maps, searches and acknowledging alerts keep working.
  - From anywhere: the API token as a parameter (CVE-2026-86426, no login needed), SQL in the notification id (CVE-2026-109353), the address search (CVE-2026-26990), the API sort order (CVE-2024-32480) and the package search (CVE-2024-32461), shell characters in device host names (CVE-2024-51092), quotes and line breaks in graph parameters (rrdtool, CVE-2026-86427 and older), the password in the query string (CVE-2023-46745), .. in NfSen channels (CVE-2026-109354).
  - Not ticked by default: HTTP Basic authentication from outside (CVE-2026-109357; leave it off when people use http-auth from outside) and the API from outside (the LibreNMS mobile app uses it).
  - Every rule's own requests were replayed in a real nginx + ModSecurity 3.0.9 and 3.0.17 + CRS 4.30 sandbox: each attack refused by its own rule, each ordinary request touched by no rule.
- A parameter rule can name a PHP array field (notification_id[]), which ModSecurity keeps as a name of its own.

## 0.5.49 (2026-11-28)

- Synology DSM protection set (from published advisories and research, measured on DSM 7.4):
  - "Administration APIs from the local network only" also covers Security Advisor (SYNO.Core.SecurityScan; CVE-2026-124993 needs no login).
  - "Parse every body as DSM does" and its two companions also cover the package programs (`/webapi/AudioStation/*.cgi`, `/webapi/DownloadStation/*.cgi`): measured, these read any body that is not multipart as a form, like entry.cgi, so another content type could still carry parameters no rule saw there.
  - "File paths with ../" also checks the File Station, Synology Drive and Download Station parameters that name a destination, a new name or the files to copy (dest_file_path, goto_path, new_name, to_parent_folder, files, destination).
  - A batch request (compound) with the markers of the login attack CVE-2024-10441 (PLUGIN_VALUE_END, LD_PRELOAD= and the like) is refused too; the login fields also know LD_LIBRARY_PATH and LD_AUDIT.
- QNAP QTS protection set (from published advisories and research; there is no QNAP here, so rules not measured are not ticked by default):
  - New: X-Forwarded-For with shell characters or over 512 bytes (Notes Station 3 CVE-2026-34007 into a shell command without a login; the authLogin.cgi overflow CVE-2017-17029).
  - New: NTP server, task id or hash with shell characters (VioStor CVE-2023-47565, CISA KEV, used by Mirai; EDB-41842).
  - New: password, user name or language over 1024 characters (ZDI-17-1003, 1006 to 1008, overflows before a login).
  - New: upload file names over 255 bytes (File Station 5, CVE-2026-26239 to 26241), not ticked by default: a Chinese name of about 86 characters is already 256 bytes, and this has not been measured on a real NAS.
  - "File names and paths with ../" checks 10 more File Station parameters; the session cookie rule also checks NAS_SID and ../ (CVE-2019-7193).
- Confident blocks: a new target, the upload file name (multipart; ModSecurity's FILES); the `arg` target takes up to 24 parameter names (12 before).
- The sandbox gives each request its client address in a header of its own, `X-JTWAF-Client` (it was X-Forwarded-For, so a test could not send an X-Forwarded-For of its own).
- Sites page, "Example for a new site": off port 443 the Host header passed to the back end keeps the port. DSM builds its redirects from Host, and without the port Surveillance Station and others were sent to port 443 (it happened on our own site). New QNAP QTS type.
- Project site: a new page of reverse proxy examples (a web site, WebSocket, Synology DSM, QNAP QTS) with the reasons behind each setting; the examples are generated by the program, the same as on the sites page.

## 0.5.48 (2026-11-28)

- The CRS score refusing outside requests: on a host adopted from a fresh ModSecurity (engine in detection only) the CRS score only logged, also for outside sources; only the confident blocks refused. The configuration names the rule that should do it (`waf.threshold_rule_ids`, 10297), but nothing wrote it. The dashboard's "not set up yet" card now names it and proposes the rule in one click (a change: checks, sandbox, approval): outside sources at or over the threshold are refused, internal ones keep being logged. Command line: `jt-waf-mgr scoreblock status|propose`.
- Application protection sets can bring exclusions: known false positives of the application's ordinary use, excluded as narrowly as possible (one path, the parameters or rule named). An exclusion loosens, so approving it needs a one-time code; it is ticked by default only when the CRS score refuses outside requests on the host. Proposing the CRS score refusal brings these exclusions for the sites running such an application in the same change.
- Synology DSM protection set (measured on a DSM 7.4 site):
  - The labels the Synology Photos app sends with a photo (raw_data, for example watch, time, cat) and its field list (additional) are left out of the command injection rules; every other rule still checks them. Without it, once the CRS score refuses outside requests, backing up photos from outside fails.
  - DSM web interface: an API name at the end of the path (for example `.Profile`) taken for a restricted file (930130), settings JSON in the data parameter taken for SQL injection (942550), and settings saved by the browser's sendBeacon as text/plain (920420), each excluded as narrowly as possible.
  - DSM reads any request body that is not multipart as a form, whatever its Content-Type says (text/plain, application/octet-stream, made-up types, or none), while ModSecurity parses only the types it knows: another type could carry parameters no rule sees. Two new rules make ModSecurity parse such bodies of `/webapi/*.cgi` as a form, like DSM (always recommended).
  - "Request bodies ModSecurity did not inspect" is ticked by default only when the site's nginx configuration has the Synology Photos for iOS fix: Photos for iOS uploads in a multipart form ModSecurity cannot parse (a charset parameter before the boundary), and without the fix those uploads are refused from outside. A site with that rule applied and no fix is named on the dashboard as important. The Synology example on the sites page now includes the fix (only that form is rewritten to the standard one and inspected in full by a loopback server).
- QNAP QTS protection set: "request bodies ModSecurity did not inspect" is no longer ticked by default; the upload formats of the QNAP apps have not been measured on a real QTS.
- Support bundle: the events page (approvers and admins) and `jt-waf-mgr support-bundle` put the events of a range into one zip with the text of the rules that decided them, the managed rule files, ModSecurity and CRS settings, the nginx server blocks of those sites (secrets masked), the system check, the changes of the range and the software list, to send to whoever helps analyse a false positive. Source addresses are replaced by names by default, site names optionally; never passwords, tokens, keys, the audit trail, access logs or request bodies. Every bundle is audited.
- Alerts: several can be selected and marked handled at once (one note, each audited on its own); the buttons of the handling form no longer touch the note box.
- Events: a chart of the source addresses (top 10, filter or exclude from it).
- LLM settings: when the saved model is gone from the server (the server switched models), the connection test still fills the model list with the server's models and marks the saved one "not on the server"; the list used to offer only the server default and the saved model. The same for the threat intelligence model.
- System check and health API: while the apply program has written the files and waits for old nginx workers (up to `apply.wait_old_workers_seconds`), it shows "being applied" instead of "failed, changed outside".
- Log shipping: WAF events carry the source country (GELF `_country`, `_country_name`; the same fields in CEF, LEEF, JSON and kv; left out for internal or unknown addresses) and the site name (GELF `_site`: Graylog drops `_host`).
- Graylog content pack (`deploy/graylog/`): streams, a pipeline, dashboards and event definitions, verified on Graylog 6.3 and 7.2.

## 0.5.47 (2026-11-25)

- Sandbox: an ordinary test request of a confident block that the rules in place already refuse (a protection set's WebDAV request on a site whose CRS does not allow WebDAV methods, a content type the CRS does not allow) is judged against the configuration as it is: it fails the change only when one of the change's own rules matches it. An exclusion's ordinary tests are never excused this way, since letting them through is what the change must do.
- Application protection sets: Zimbra's proxy rule had an ordinary test the CRS refuses by itself (a URL with an address), replaced with one using a host name.

## 0.5.46 (2026-11-25)

- Evidence for a confident block: requests from inside fail the check only for a rule that refuses inside sources too (source "all"). A rule refusing outside requests only never sees them, so administrators opening the admin pages from inside (or Nextcloud's own check of its data directory) no longer fail it; they are shown with the evidence. Applying a rule by itself (automatic tightening) still needs no request from inside.
- Application protection sets: ordinary test requests that another rule of the same set refuses were replaced (Nextcloud app management and the X-Forwarded-Host rule, Zimbra's admin cookie and proxy rules, QNAP's file name rule): a set is proposed as one change and its sandbox sends every test through every rule. A unit test now checks every set as a whole.

## 0.5.45 (2026-11-25)

- Confident blocks: a second range of rule ids, `waf.confident_range2` (default 11000-12999), used once `confident_range` (10200-10296, 97 ids) is full. A protection set takes one id per rule and site, and proposing the Nextcloud set and the Zimbra set for three site names on one host failed with "id range full". Ids in either range count as confident blocks everywhere (events, the rule list, the analysis, automatic blocks). An existing `confident_range` in config.toml is kept; set `confident_range2 = []` for none.

## 0.5.44 (2026-11-25)

- Application protection sets: Nextcloud (22 rules, 16 recommended) and Zimbra (20 rules, 16 recommended), for the sites the software list names as Nextcloud or Zimbra. Written from public sources (vendor advisories and source code, CISA KEV, NVD, Rapid7, Volexity, nuclei, Metasploit, the CRS Nextcloud plugin) and checked against the access logs of real sites; each rule's attack and ordinary requests pass on real nginx with ModSecurity 3.0.9 and 3.0.17 and CRS 4.30.
  - Nextcloud: the directories and files its own nginx example refuses (config, data, lib, occ, .htaccess, composer.json ...), release files that reveal the version, app internals (appinfo, vendor, tests), a ../ segment in the path as sent (also encoded several times), the built-in CODE server's command injection (CVE-2026-110447, CISA KEV) and X-Forwarded-Host with shell characters (CVE-2025-66208), the updater, web upgrade and OpenMetrics from outside, the installer form, share tokens that cannot exist, the PDF.js development viewer (CVE-2025-59788), a WebDAV Destination with ../, Collabora's admin console. Not ticked: administration and app management from outside, user administration actions, federated shares, cron.php, the built-in CODE server when unused.
  - Zimbra: administration services and mboximport on the user port (CVE-2022-27925, CVE-2022-37042), several logins in one GraphQL request (CVE-2026-93637, not fixed in 10.1.21) and GraphQL over GET or a form, LDAP wildcards in login names (CVE-2026-93635), internal servlet attributes as parameters (CVE-2025-68645, CISA KEV; CVE-2026-50053), direct /h/rest, line breaks in the path, zimlet and /downloads JSPs, WEB-INF paths, file names with WEB-INF or ../, markup in identifier parameters (reflected XSS, CVE-2023-37580 and others), the proxy servlet aimed at internal addresses, the admin cookie on proxy and upload paths, GraphiQL, sfdc_preauth.jsp. Not ticked: JSPs not shipped with Zimbra, /m/, the proxy servlet and EWS from outside.
  - A header rule's details name the header; tests may use WebDAV methods (PROPFIND, MOVE, COPY ...).
- Confident blocks on a request body ModSecurity did not inspect: the evidence check now looks at ModSecurity's own records of the bodies it could not parse or that were over its limits (its rule 200002), and fails when one was answered 2xx/3xx from outside (or came from inside) on a site and path the rule covers. It used to be skipped, and such a rule on all sites refused some of Zimbra's web client SOAP requests (JSON ModSecurity cannot parse: saving a draft, sending, preferences); the paths of such requests go in the rule's exceptions.

## 0.5.43 (2026-11-24)

- System alerts in the interface language: a CRS update, the IP block list being full, the IP block list or the country lists not being written, a traffic spike and many 5xx were shown with their English reason in the Chinese and Japanese interface and notifications. They now carry a message key and its values, worded in the reader's language on the page and in notifications; older alerts are worded the same way when their values are there, otherwise they keep their reason.
- Project site: thumbnails are now a separate, smaller picture (1200 px; clicking opens the full one) instead of the full screenshot shrunk by the browser, which blurred the text; the IP intelligence picture is shown whole instead of cropped at the sides; the threat intelligence card is shorter.

## 0.5.42 (2026-11-23)

- Security: a request body larger than ModSecurity's body limits (`SecRequestBodyLimit` for an upload, 12.5 MB by default; `SecRequestBodyNoFilesLimit` for a form or JSON, 128 KB by default) or one it cannot parse was passed on with none of it inspected, because the engine runs in DetectionOnly and jt-waf-mgr blocks from its rules (`SecRequestBodyLimitAction Reject` then never rejects). Every rule that looks into the body was affected: the CRS, confident blocks on a parameter, the application protection sets. Tested on nginx with libmodsecurity 3.0.9, 3.0.14 and 3.0.17.
  - Confident blocks: a new target, "Request body not inspected" (`body_unchecked`, `REQBODY_ERROR` / `INBOUND_DATA_ERROR`), with no pattern; the paths that take large uploads go in its exceptions.
  - Application protection sets: Synology DSM and QNAP QTS each have a recommended rule refusing such requests from outside (11 and 8 rules). A site with a set applied shows it as available: propose it from the protection sets page.
  - System check: "Request bodies ModSecurity does not inspect" lists the sites with ModSecurity on that take larger bodies with no rule for them.
- System check "Large uploads and memory": counts the part ModSecurity inspects, which costs several times its size and is slow (measured with the CRS 4.30 on an 8 GB host: 256 MB took 2.1 GB at about 4 MB/s, 512 MB took 4.2 GB), and warns above half of the host's memory.

## 0.5.41 (2026-11-23)

- Threat intelligence: QNAP's own security advisories, a new source (Settings, threat intelligence, "QNAP security advisories"; off by default). When the software list has a confirmed QNAP product, the threat intelligence job downloads the RSS feed of qnap.com once a day (about 16 KB, the 20 newest advisories; those seen before are kept, up to 300) and hands the advisories of the last months to the model, those naming a confirmed product first, to read each advisory page for the affected and fixed versions. qnap.com is among the domains the model may read (a new installation's default list; an existing list set in the web UI is kept as it is).

## 0.5.40 (2026-11-23)

- Application protection sets: a second set, QNAP QTS (7 rules, 6 recommended), for sites the software list names as QNAP QTS. From outside: the setup wizard quick.cgi (CVE-2023-47218, CVE-2023-50358); HBS 3's built-in session id in a query, form or JSON body (CVE-2021-28799, Qlocker, CISA KEV); a ../ step in a file name or path parameter (Photo Station combine.php and video.php: CVE-2022-27593 DeadBolt, CVE-2019-7194/7195, CISA KEV); a sid, ssid, name or p over 2048 characters (share.cgi CVE-2024-27130, Surveillance Station CVE-2021-28797); a user name with shell characters (CVE-2024-32766); QPS_SID / QMS_SID / QMMS_SID cookies with shell characters (authLogout.cgi). Not ticked: all of Photo Station from outside. Written from public write-ups (vendor advisories, Rapid7, watchTowr, Unit 42, SSD, nuclei, Metasploit, CrowdSec) without a QNAP at hand; each rule's attack and ordinary requests pass on real nginx with ModSecurity 3.0.9 and 3.0.17 and CRS 4.30.
- Software versions: a QNAP QTS site's firmware version and build from /cgi-bin/authLogin.cgi, which answers without a login (not yet seen on a real QTS 5.2).
- Protection sets page: QNAP advisory numbers (QSA-, NAS-) in the source labels.

## 0.5.39 (2026-11-22)

- Sites page, "Example for a new site": pick the kind of site (a general reverse proxy or Synology DSM), give the name, port, back end, upload limit and certificate (one the sites here use, or your own paths), and get a whole server block, where to save it and the commands to load it, to copy. jt-waf-mgr writes nothing: an administrator saves it, runs `nginx -t` and reloads, then switches ModSecurity on from the sites page. The example replaces X-Forwarded-For (never appends), adds a default server on a port other than 443 that refuses a TLS handshake for any other name, starts local-network-only, and warns about an upload limit too large for ModSecurity; the Synology one adds WebSocket, unbuffered uploads and DSM's trusted proxy. All three kinds pass `nginx -t` on nginx 1.28.
- Sites page, "View configuration" on each site: the server block nginx has loaded (read only, secret-looking values masked); only blocks nginx loads, never any file. Both for approvers and administrators. `GET /api/v1/vhosts/config`, `GET /api/v1/vhosts/example`.

## 0.5.38 (2026-11-22)

- The evidence check no longer counts jt-waf-mgr's own requests as people using a path: reading software versions and home pages, the health checks around an apply (from this host, with jt-waf-mgr's own User-Agent). revproxy2's Synology set failed it on "old DSM CGI programs" because of the program's own GET /webman/info.cgi for the DSM version, while all 139 sandbox requests passed.

## 0.5.37 (2026-11-22)

- Important fix: on a host adopted with a fresh ModSecurity (no site rule file), confident blocks, country limits and CrowdSec rules only logged and never refused: they mark `tx.jt_block`, and the system rule 10298 that turns the mark into the critical anomaly score for the CRS to refuse the request came only with rule files adopted from a site. The managed before file now carries it at its end when none is there (one a person deleted stays out). Found when revproxy2's first Synology protection set answered every attack request with 200 in the sandbox while matching it.
- The host's name ([node] id, at the top of every page and in the audit events) defaults to the host's short name (hostname -s); the example configuration no longer sets "waf1", and an upgrade turns a configuration still at the example's `id = "waf1"` to the host's name.
- Rules list: the rules of an application protection set have their own author, "Application protection sets", to filter on (they were under jt-rules).
- Synology DSM protection set: "Video Station subtitle code page": the subtitle program passed subtitle_codepage to a command (Talos / Snort 1:36031); from outside, one with a command character, a quote or a line break is refused (10 rules, 9 recommended).

## 0.5.36 (2026-11-22)

- System check: "Large uploads and memory". nginx's ModSecurity module reads a whole upload into memory first, whatever the body limits say (measured with libmodsecurity 3.0.14 and module 1.0.3: a 1 GB upload took an nginx worker to 1.6-1.9 GB; 8 MB with ModSecurity off). A site with ModSecurity on that accepts uploads without a limit or above a quarter of the host's memory is a warning, naming the site's locations already without ModSecurity. The ModSecurity manual explains it in three languages.

## 0.5.35 (2026-11-22)

- Synology DSM protection set, "administration APIs from the local network only", narrowed so ordinary users are not refused: checked against the scripts of the packages on the NAS and of DSM Help, the DSM address settings (SYNO.Core.Web, which Synology Photos builds links from) and the DDNS records (DSM Help) are no longer in it; for the network only its sub-APIs are (PPPoE, for example), the basic network information stays readable; for file services only the FTP, NFS, rsync, AFP and WebDAV settings (the SMB status stays readable). A site with the earlier rule shows "update available" on the protection sets page.

## 0.5.34 (2026-11-22)

- Threat intelligence: Synology's own security advisories, optionally (Settings → Threat intelligence → "Synology security advisories", off by default). With a confirmed Synology product in the software list, the threat intelligence job downloads Synology's advisory feed from synology.com once a day (about 450 KB, every advisory since 2013) and checks it; the advisories of the last months go to the model, which reads the advisory pages for the affected and fixed versions; those naming a confirmed product come first. The web service itself never connects out.
- Dashboard: a site running software with a protection set whose recommended rules are neither applied nor in a change is an important item ("Synology DSM: 8 recommended protection rules not applied", for example), leading to the protection sets page.
- Dashboard: the hints did not fill in their values: "OWASP CRS {version} is downloaded but not installed" showed {version} as is.
- Outside changes: the first installation of OWASP CRS on a host (an approved change; jt-waf-mgr writes the rules, crs-setup.conf and two Include lines in the ModSecurity main file) was recorded as an outside change with a critical alert. These files are now jt-waf-mgr's own change, and so are those of a CRS version switch (the main file not among them).

## 0.5.33 (2026-11-22)

- Application protection sets (Rules menu): ready-made confident blocks for one application, written from its publicly known vulnerabilities and attacks, each with its CVEs, sources and tests (its attack requests must be refused, ordinary ones let through). Every site the software list names for the application is listed; the picked rules are proposed as one change: the usual checks, the sandbox, a person's approval, never applied by itself. A rule a later version writes differently shows "update available" and is modified in place. `GET /api/v1/protsets`, `POST /api/v1/protsets/propose`.
- The first set is Synology DSM, 9 rules, refusing requests from outside only: administration APIs from the local network only (Task Scheduler, SSH, groups, network, firewall, package installation, Container Manager, Hyper Backup, snapshots, storage...), batch requests with escaped letters, login fields with control characters (CVE-2024-10441), redirect addresses with a line break (CVE-2024-50629), old DSM CGI programs (imageSelector.cgi of SynoLocker, info.cgi that tells the version and serial number, ...), Photo Station's PHP pages, file paths with ../, Drive's local-only login flag (CVE-2024-50630), and, not ticked by default, the Synology Photos live channel (CVE-2024-10443). Measured on DSM 7: DSM picks the API from the api parameter only (case-sensitive names, the last one when sent twice), a batch request's compound parameter carries other APIs, and JSON \u escapes in it get past text matching; every test request was replayed against ModSecurity 3.0.14.
- Confident blocks: a new target, a parameter's value (`target: arg`), for the parameters it names (query string or form; several names with `|`).
- The software list recognises a Synology DSM's packages: DSM lists the APIs it serves without a login (SYNO.API.Info), which names 30 packages such as Synology Photos, Drive and Surveillance Station; `api=SYNO.…` in the access log counts too. The DSM version is read from info.cgi. A DSM home page whose title starts with the host's name was not recognised.
- Sites not on port 443 (DSM on 5001, for example): the home page guess and the version reading connect to the site's own TLS port; they always used 443 and could read another site.
- Threat intelligence may read php.net and synology.com by default (new installations; an existing setting stays).

## 0.5.32 (2026-11-21)

- CrowdSec page: the sync is turned on and off right there (administrators), not only on the settings page; the dashboard's hint leads to it.
- Dashboard hints: a CRS that is downloaded and verified but not installed says so and what is left (a reason, "compare in the sandbox and propose", the approval), and a proposed installation names its change; the CRS page's switch only turns on the downloads. One person who can approve with single-admin mode off is an important item: every change would wait for ever.
- Change page: the note that only single-admin mode lets you approve your own change, and the refusal, link to where it is turned on.
- A request under way shows a spinner: the CrowdSec sync (its badges and button), the CRS check and upload, the event analysis.
- CRS page: the reason for a switch is optional, and the proposal stands apart from the offline upload with room around its button.

## 0.5.31 (2026-11-21)

- Dashboard: when something important is not installed or not turned on, a card at the top names it, says why it matters and links to where it is set up: OWASP CRS not installed, the ModSecurity configuration not adopted, no site with the WAF on, the apply program not enabled, notifications off, CrowdSec virtual patching off. Features worth turning on (event analysis, threat intelligence, IP reputation, country lists, temporary IP blocks) are folded inside it. A fully set-up host shows nothing. `GET /api/v1/readiness` gives the same list.
- System check: the ModSecurity card says when the CRS is not installed and links to the CRS page.

## 0.5.30 (2026-11-21)

- Sign-in and first-login pages: a soft glow in the logo's colours over a faint dot grid and a lifted card with an accent edge, in place of a flat, empty background (the dark theme looked all black).
- Dark theme: filled blue buttons, selected segments, chips and calendar days use white text on a deeper blue (4.8:1); the dark text on the lighter blue was hard to read.

## 0.5.29 (2026-11-21)

- A vhost file added to an include directory by hand (a new site in `sites-enabled/`) was not seen by the web service: its cached view of the nginx configuration was re-read only when a file it already knew changed, so the site list missed the new site and, when a command-line check saw it, the outside-change record flapped between "added" and "removed" with one critical alert each time. The view now also notices files appearing in or leaving an include pattern, and the configuration fingerprint always looks at the files as they are.
- Outside changes, who was logged in: OpenSSH 10 (Ubuntu 26.04, Debian 13) logs sessions as `sshd-session[…]`; these lines were skipped, so every change on such a host said no login was recorded.
- ModSecurity manual: the Ubuntu 26.04 package line (libmodsecurity 3.0.14, `libmodsecurity3t64`).

## 0.5.28 (2026-11-21)

- Threat intelligence, this host's packages: when several installed packages give one product, the newest version stands for it. A host upgraded from Debian 11 keeps the old `libssl1.1` (1.1.1w) next to `libssl3` (3.0.22); taken in name order the old library won, so OpenSSL was listed and searched as 1.1.1w and its advisories were judged against a library nginx does not load. An entry guessed this way follows the newest package at the next run; one a person typed is left as it is.

## 0.5.27 (2026-11-21)

Fixes from an independent review of the automatic blocks:
- A blocked address protected afterwards (Settings: protected networks, known scanners, the internal networks) has its block ended, audited. The apply program refused the whole IP block list with it in, so new blocks were not written and ended ones not taken out, with a critical "block list not applied" alert every few minutes, until that block ran out (up to 30 days; a permanent one never).
- An address the secret-file probe rule could not block for a passing reason (the list not loaded, full) is tried again later; it waited for a restart of the service.
- NAT64 (`64:ff9b::/96`) and the benchmarking range (`198.18.0.0/15`) are not taken for addresses on the internet and are never blocked.

## 0.5.26 (2026-11-21)

- nginx update's hot switch: a new nginx master that does not come up in time is stopped (QUIT, then TERM) so the old one is the only master again before the failure is reported. It was left running beside the old one, sharing its listening sockets, and later reloads reached only one of them while the other kept the old rules (found by an independent review, reproduced on a lab host: two masters and nginx.pid.oldbin left behind; after the fix, three forced failures each left one master and the site answering). The wait for the new master is 45 seconds instead of 15, so a large configuration is not given up on too early.

## 0.5.25 (2026-11-21)

Fixes from an independent review of 0.5.0–0.5.4:
- With nginx security updates applied by themselves (`nginxup.auto_update`), a version an administrator rolled back from is no longer proposed and applied again by itself (it went back up within minutes of the rollback); a newer version, or a person proposing it, starts over. With it off, it is no longer proposed again on every check.
- Switching on `nginxup.auto_update` from the command line (`settings set`, `settings import`) needs a one-time code (`--totp`), as in the web interface.
- nginx configuration backup: files the configuration names as secrets (`ssl_certificate_key`, `auth_basic_user_file`, `ssl_password_file`, `ssl_session_ticket_key` ...) and basic-auth password files by any name are left out, whatever they are called.
- One open nginx change at a time is checked in the same database statement that adds one (the job's own proposal and an administrator's rollback could both be added).

## 0.5.24 (2026-11-21)

Fixes from an independent review of 0.5.5–0.5.9:
- A threat intelligence virtual patch on a parameter's name accepts names written out only (`^name$` or `^(?:name1|name2)$`). Patterns such as `^json\..*$` (every JSON body) or `^.{20,}$` (every long name) passed every check, the access logs cannot show a parameter's name in a body, and an exploited flaw's patch applies by itself.
- Attribution of configuration changes: a file an nginx update installed counts as jt-waf-mgr's change only while it still has the package's recorded hash (dpkg md5sums, conffiles). Being in the package's file list was enough, so an edit of nginx.conf within half an hour of an update was taken for the update and raised no "changed outside" alert.
- Debian security tracker: when another version of the same source is listed (php8.4 listed, php8.2 not), the answer is "not triaged yet", asked again, instead of "another program's CVE", which set the threat aside.
- A security release notice with a date and no time counts that day as over everywhere; it was 00:00 UTC, so a release later that day was dropped and the search after the release could run before it. That search is marked done only when its run ends well.
- An approved change is not sent to the apply program a second time (with another version number) when an error comes after its request went; one change is sent at a time (two processes approving two changes at once could send both with one version number).

## 0.5.23 (2026-11-21)

Fixes from an independent review of 0.5.10–0.5.16:
- A threat intelligence virtual patch for several sites applies to those sites only. Two or more sites (one PHP flaw for Nextcloud and Z-Push) became "every site", so a parameter name chosen by the model was blocked on unrelated sites too. Only this host's own software (nginx: no sites) is every site. Rules already in force are not changed by themselves; propose one again to narrow it.
- A virtual patch the access logs cannot check is not applied without a person when the sandbox did not really run (with "sandbox required" off).
- Pages and texts handed in to the threat intelligence: when the run is stopped (its time limit, a restart) they are marked failed instead of "running" for ever, counting against the waiting limit; a misconfigured search service ends the run with its error recorded. A threat read from a pasted text (no address) is no longer dropped for having no reference; a page that refuses programs is replaced by the pasted text when there is one.
- Event analysis: requests whose answer was cut short count toward the token use and limits.
- A virtual patch applied as a bundle of CrowdSec rules (from the CrowdSec page) is no longer unlinked and linked again every run, and its alerts name the rule.
- A wildcard site name (`*.example.com`) is tested in the sandbox as `www.example.com` for a virtual patch.

## 0.5.22 (2026-11-21)

Fixes from an independent review of 0.5.17–0.5.21:
- Notifications: an alert's notification is worded from the alert's own details. It was taken from the audit record, which carries a fixed few fields, so the notifications of "nginx security update" (since 0.4.98), "security release notice", "back-end nginx" and the back-end PHP urgent alert had blank versions, CVEs, sites and titles.
- nginx threats: whether one is set aside is decided with this host's nginx version from the software list's entry for this host. Without a version from the caller it was the threat's own version, which, once a back-end nginx was listed, joins every version ("1.22.1, 1.30.7"): only the first was read and this host's was never compared, so an advisory affecting this host could be set aside.
- Back-end versions: each site is asked with its own name and a version counts only for the site asked (an address serving several sites credited the first one's PHP to all); a site behind two back-ends keeps both versions, and one inside the affected range is enough (the last one read stood for the site).
- Back-end versions: a site no longer passed to a private back-end (gone from nginx, now a public address or a socket) leaves its entries; with "Read the back-end hosts' versions" switched off, the entries the probe made go and their alerts are handled. They stayed, and their old versions kept deciding.
- When nginx.org's advisories cannot be read, the "back-end nginx" alerts stay open (they were all handled as "no longer listed").
- Security release notices: a title with a range ("and earlier", "before", "up to") does not close by itself; the newest version named on a branch is the release ("1.30.6 → 1.30.7" does not close with 1.30.6 installed); a language known only from back-end hosts (PHP) is judged only when every site of the applications on it said its version.
- A back-end address written as IPv6 for an IPv4 one (`::ffff:8.8.8.8`, 6to4) is judged by its IPv4 address (Python 3.11 calls `::ffff:8.8.8.8` private).

## 0.5.21 (2026-11-21)

- Threat intelligence: the "the search service gives no web page" alert is one alert while the problem lasts (it was one a day, one more for each day the service stayed broken); an older duplicate is merged into the first one, and it is handled by itself once the searches give web pages again.

## 0.5.20 (2026-11-21)

- Threat intelligence: a notice of an announced security release closes by itself when every version of the product in the software list already includes the release named (the same branch at that version or later, or later than every version named), with the installed version as the reason. The notices of nginx 1.30.7 and ModSecurity 3.0.17 stayed open after the approved updates installed them. A notice that names no version, or an installed version older than the release (a distribution's package may carry the fix, which is not known here), stays open.

## 0.5.19 (2026-11-21)

- The software list's home page guess and the back-end host versions include the sites nginx serves on any TLS port (`listen 12443 ssl`), not only 443. Where nginx's stream block on 443 passes each name to its own port by SNI, those sites (mail, ActiveSync) were never asked. A name not passed on that way meets another certificate at 443, and the certificate check refuses the answer: another site's page is never read.
- Threat intelligence: an open threat's alert follows the current finding. An alert raised as "NVD lists only other products: probably attributed to the wrong product", for a flaw NVD lists in the language an application is built on (PHP), is reworded on every run to "the flaw is in PHP: check the PHP on its host" (before, only a run in which the model reported the same threat again rewrote it, so it stayed as it was); when the PHP the back-end host runs is inside the affected range and the flaw is exploited, an urgent alert replaces it.

## 0.5.18 (2026-11-21)

- Threat intelligence: when NVD lists a flaw in the language an application is built on (PHP for Nextcloud) and the back-end hosts said the running PHP version ("Read the back-end hosts' versions"; `X-Powered-By` is the running PHP's own word, more telling than `php -v` on the command line), that version is compared with NVD's affected range: outside it on every site of the application -> not affected; inside it on a site, and not a distribution's package -> an urgent alert when exploited, to update PHP on that host and restart its processes. A site that did not say, or a distribution's package (fixes may be backported), keeps the earlier "check the PHP on its host".
- A distribution's PHP version said by a back-end host keeps its suffix (`8.1.2-1ubuntu2.14`), not only the upstream version.
- The threat details' "Affected versions (NVD)" showed a raw dictionary key (`intel.nvd_versions_built_on`) instead of a sentence for a flaw in the language an application is built on (since 0.5.12).

## 0.5.17 (2026-11-21)

- Threat intelligence can read the back-end hosts' versions (Settings → Threat intelligence, "Read the back-end hosts' versions", off by default). nginx does not pass a proxied server's `Server` header on, so only this host's nginx version was known, not the nginx, Apache or PHP a back-end host runs. When on, before each search one `GET /` goes to each private address the nginx configuration's `proxy_pass` points to (`upstream` groups included), only the answer's headers are read, and the product and version from `Server` and `X-Powered-By` are listed in the software list, marked "back-end host" with the sites it serves; a changed version is updated, its confirmation kept. The addresses stay on this host and are never sent to the model.
- A back-end host's nginx is compared with nginx.org's security advisories: an affected version raises a "Back-end nginx" alert (a warning: the features that host uses are not known, and a distribution's package may carry backported fixes), closed by itself once the back-end is updated. Updating this host's nginx does not close it. An nginx threat is set aside by the advisories only when neither this host's nginx nor a back-end one is affected.

## 0.5.16 (2026-11-20)

- Event analysis: an answer cut short by the output limit is asked again at once with twice the room (up to 16,384 tokens), and a batch starts with room for a model that thinks before answering (at least 4,096 tokens instead of 512 + 320 per candidate). After the local LLM server switched to a model that thinks longer, every run failed: the model was still thinking when the limit ran out, the server refused the unfinished JSON with a 502, and the same request was tried three times. Such a failure is shown as `output_truncated` with what to do, in the analysis page and the notification, instead of a bare `http_502`. AI analysis of a single event does the same (twice the room once).

## 0.5.15 (2026-11-20)

- Threat intelligence: a flaw whose virtual patch written by the model is in force for one application gets the same rule for the other applications it reaches, without asking the model again. Asked once more about Nextcloud and Z-Push together, the model answered "not possible" for the PHP flaw (CVE-2026-115560) it had written a parameter-name rule for on LibreNMS; such flaws get the rule now. A rule a person removed is not copied.

## 0.5.14 (2026-11-20)

- Threat intelligence: a threat's virtual patch follows the rule in force. A CrowdSec rule removed as a duplicate (its sibling covers every site) kept being named as the patch, and threats whose rule is in force named the rollback that had last rewritten every rule. Links to a rule no longer in force are dropped and matched again to a rule that is (a rule a person removed is not proposed again), and the alert names the rule (rule 10402), not a change.
- The warning for a flaw in the language an application is built on (PHP) also says to restart the running PHP processes or rebuild the container image: a PHP-FPM worker left running keeps the old version, and the command-line `php -v` does not show it.

## 0.5.13 (2026-11-20)

- Threat intelligence: an exploited flaw in the language an application is built on (PHP for Nextcloud, LibreNMS, Z-Push) gets its own warning: the flaw is in PHP, whose version on that host is not known here, so check that PHP there is updated; a virtual patch already refusing the attack is named. NVD lists only php for such a CVE, and the warning used to call it "probably attributed to the wrong product; set it aside", the wrong advice for a flaw that does reach those applications.

## 0.5.12 (2026-11-20)

- nginx update page and alerts: a distribution's nginx (Ubuntu, Debian) counts an nginx.org advisory as fixed when the package's installed change log lists the fix for its CVEs, shown as "Fixed by the distribution". Ubuntu 26.04's nginx 1.28.3-2ubuntu1.12 was reported vulnerable to 10 advisories in use; its change log lists the fix for 9 of them (and for 16 of the 25 advisories its version falls in).
- Evidence check: lines of nginx's shared access.log and its rotations (access.log.38.gz) belong to the default site; the file's name was listed as a site.

## 0.5.11 (2026-11-20)

- Threat intelligence asks for one virtual patch per vulnerability, for every site of every application it reaches. A PHP flaw on three applications was asked about three times (two minutes each), and the answers differed: a patch for one application, "not possible" for the other two. Flaws left so are asked about once more, together.
- Threat intelligence keeps to its own time limit: past 45 minutes a run stops asking (pages handed in come first, then its own search results, then the virtual patches) and ends with what it found. A run the unit stopped at 60 minutes recorded nothing and stayed "running" on the page; such a run is now closed as interrupted.
- A page handed in from a site that refuses programs (HTTP 401, 403, 429 or 503, often its bot protection) says so and asks for the page's text, instead of a bare error.

## 0.5.10 (2026-11-20)

- upgrade.sh: the upgrade backups are ordered by the time in their name. A plain sort put upgrade-0.5.9-to-0.5.10-... before the older backups, so `--rollback` without a directory would have taken an old one and the clean-up would have removed the newest.
- Threat intelligence: hand it a page or a text (Threat intelligence, "Hand it to the threat intelligence"; API `POST /intel/submissions`). A news article, a vendor advisory, a post: its https address (tracking parameters such as fbclid dropped; read from that one site, public addresses only) or its pasted text. The job reads it within minutes, without the whole search, and handles what concerns the software here like its own findings: threats, virtual patches, alerts. Pages that show nothing to a program (social sites behind a login) are reported as unreadable: paste their text.
- Threat intelligence asks about each source on its own: each search result worth it (languages and frameworks first, then those naming critical or exploited flaws; 12 at most) and each page handed in gets its own short question. A small local model reading 25 search results at once once reported nothing at all. A flaw reported under a language (PHP) reaches each application here built on it.
- Fully automatic virtual patches: a threat intelligence virtual patch the access logs cannot check (a parameter name in the body, a header other than User-Agent and Host) is applied without a person once the sandbox passes, like the URL ones (the user: "fully automatic, no administrator approval"). Still only tightening, only from outside, within the daily limit unless the vulnerability is exploited and affects us; the event analysis' blocks keep needing clean evidence.

## 0.5.9 (2026-11-19)

- Threat intelligence: a search service that answers without a single web page (an encyclopedia summary, "no results") is noticed: when most of the program's own searches come back so, an alert says the search service is not searching. On 2026-11-19 every search came back empty and the run silently looked only at the pages it may read directly.
- Announced security releases: only a release with a time, still to come or out in the last 12 hours, is a notice. The model offered releases already installed here (nginx 1.30.7, ModSecurity 3.0.17) as announced.
- Integrity: files an approved nginx change put in place (a ModSecurity module root trusts, the nginx package's own files) count as jt-waf-mgr's own change. Switching the module (0.5.1) raised a critical "changed outside jt-waf-mgr" alert, naming whoever was logged in at the time.

## 0.5.8 (2026-11-19)

- Threat intelligence searches every product and every language and framework they are built on itself, once a run, and hands the results to the model. The model chose its own searches before: on 2026-11-19 it spent them on nginx and Zimbra and never looked at PHP, the day PHP announced a critical release for its sites' language.
- Announced security releases (a date set, the details withheld, or just published) for a product or a technology it is built on raise an alert and a notification: which applications and sites here are built on it, when, the vendor's interim advice; once the release is out the search runs again by itself (the hourly timer), so the CVEs and the attack can be acted on.
- Virtual patches on a parameter's name: a confident block can match the name of a parameter in the query string or the body (a form, a multipart upload part; e.g. PHP's PHP_SESSION_UPLOAD_PROGRESS), in phase 2 before the rule adding the critical score. Threat intelligence writes them for attacks in the body too. The access logs have no bodies, so the evidence check cannot look for them: such a change needs a person, except a virtual patch for a vulnerability exploited in the wild that affects us (the sandbox must still pass). Tested on real nginx with libmodsecurity 3.0.9 and 3.0.17.
- Software list: a host package's version follows the installed package before each search (nginx updated through jt-waf-mgr was still searched for as the version before).

## 0.5.7 (2026-11-19)

- Changes: approving with a one-time code (nginx updates and module switches, one's own loosening, a whole CRS category off, the event analysis's loosening) takes a note of 4 characters instead of 10; restoring the managed files after an outside edit too.
- Change page: what the approve button still waits for (a longer note, the one-time code) stands in red right above it; a grey line under the form went unseen and the button just looked broken. An nginx change no longer offers the evidence-check override, which it has no use for.

## 0.5.6 (2026-11-19)

- Changes: an approved change is handed to the apply program once. An approval made from the command line while the web service was running could send it twice; the second rendering (a second later in its header) replaced the version's recorded hashes, so the files just written looked edited outside jt-waf-mgr and the next apply would stop for it.

## 0.5.5 (2026-11-19)

- Threat intelligence: the Debian security tracker (Settings, threat intelligence; off by default). For a threat on a Debian package installed here whose change log does not name the CVE, the intelligence job asks security-tracker.debian.org for that CVE (only its id is sent; at most 20 a run, answers kept a day). Fixed in the installed version, marked not affected, or listed for other packages only (a CVE of another program attributed to a library: "use after free in XML in Google Chrome" is Chromium's, not libxml2's) sets the threat aside and handles its alerts; fixed in a newer package of the release says to update it, and an exploited one then takes the urgent path. Packages from elsewhere (nginx.org's nginx) are never compared with Debian's versions.
- IP lookup: the two blocked-vs-logged bars stand one above the other beside the map; side by side they left the map's height empty below them.

## 0.5.4 (2026-11-19)

- IP lookup: the chart titles under the number cards (blocked vs logged for 7 and 30 days, the location) keep a gap from the cards; they sat right against them.
- Change reasons the system writes (rules written again, event analysis, threat intelligence, nginx updates, HTTP/2 off and on, pausing the WAF) read in the page's language. They were stored and shown in English only; the stored text stays English (CLI, audit trail, the rules file), and reasons written by earlier versions are recognised too, so a change already waiting (such as rules written again in 0.4.93) reads in Chinese now. Words a person or a model wrote inside a reason are shown as written.
- Change titles: nginx updates, HTTP/2 or HTTP/3 switches and WAF pauses have names (the page showed op.proto and the like).
- Chart titles that follow another chart (its legend or bars) keep room above them, on every page (events: attack types and the country map sat right under the legend above).
- Events: the note for the `_other` site filter sits on its own row; inside the field it made that field taller and pushed the filter row out of line.
- CrowdSec rules: several CVE numbers stand one a line, so the description keeps its room.
- War room globe: zoom in, zoom out and reset size (buttons and keys) glide to the new size instead of jumping; the wheel and a pinch still follow the hand.

## 0.5.3 (2026-11-19)

- Threat intelligence: an open threat's three panels (versions, the attack, exploitation) fit the table's width. A long reference address used to widen the whole table, so on a laptop screen the panels had to be scrolled to sideways; the address is now cut with … (the full address on hover), and the panels sit three in a row whenever there is room for them.

## 0.5.2 (2026-11-19)

- Temporary IP blocks: adding a block (the API for fail2ban and others, or the page) is refused with 409 `list_not_loaded` while nginx does not include the block list in http { }. The block used to be written and reported as done while nginx never read the list, so the caller believed the address blocked.
- Change previews: lines taken out show in red and lines put in show in green (HTTP/2 or HTTP/3 off and back on, a site's WAF switch, the block page), and the marks show the change's own number (they read "change #0").
- The backup's manual steps (RESTORE.txt) are complete in Japanese too (they were a summary); the nginx update job's descriptions say every 6 hours (they said daily). Reported by the blog writer.

## 0.5.1 (2026-11-19)

- If an nginx update goes wrong: the nginx updates page and the approval page of an nginx update now show, before anyone approves, what happens by itself (the previous package and module kept, health checks, everything put back on failure, a critical alert if even that fails), how to go back and what to do when the page cannot be reached.
- Roll back to the previous nginx: the root program keeps the previous package and module of the newest successful updates; "Propose rolling back" (or `jt-waf-mgr nginx rollback`) proposes going back to them as a change an administrator approves with a one-time code. Root checks that nginx is still what that change installed, verifies the kept package against apt's index (or the SHA-256 kept with it) and the old module with the old nginx, then moves nginx back without stopping it, with the same health checks and the way back on failure.
- Use another ModSecurity module: a module root trusts (built against another libmodsecurity, for example) can be switched to for the installed nginx, the same way (`jt-waf-mgr nginx module SHA256`).
- Download a backup: the nginx configuration, the module in use and the steps to put them back by hand (three languages), in one file, before approving (`jt-waf-mgr nginx backup`). Private key and password files are left out; each download takes a one-time code and is recorded.
- When the management page cannot be reached through nginx: the web service does not need nginx; an SSH tunnel to `127.0.0.1:8095` and `http://localhost:8095` in Chrome or Edge works (checked), and the command line can show, roll back and approve. A manual in three languages: docs/RECOVERY.md.
- New setting "Apply nginx security updates by themselves" (Settings → nginx updates): off by default; when an administrator switches it on (with a one-time code), the update the job verified for an nginx.org advisory that affects this site is applied without waiting for approval, with the same steps and a notification.

## 0.5.0 (2026-11-19)

- Approving with a one-time code: a note shorter than 10 characters was refused only after the code had been spent, so the same code then read "enter a one-time code" and counted as a wrong code until the account was locked for a while. The note is now checked first; the approve button waits for the note and the 6 digits, and says how long the note must be; a code already used reads "this code has already been used: wait for the next one" and is not counted as a wrong code; "too many attempts" shows the seconds to wait (it showed `{retry_after}`).
- Change progress: an nginx update or another change without evidence check or sandbox showed those steps as still to do and "version {v}" when applied; they now read "not a step for this kind of change", and no version is shown where there is none.
- The browser test now fails on any unfilled placeholder on a page, and checks that the approve button waits for the note and the code.
- Version numbers: after 0.4.100 the numbering continues at 0.5.0 (no three-digit parts).

## 0.4.100 (2026-11-19)

- Approving an nginx update: the change page did not show the one-time code field the server requires for it, so the update could not be approved from the web interface (only from the command line). The page now takes from the server what approving a change requires (`approval_needs`: a one-time code, a written reason), the same rule the approval itself follows, and says that an nginx update takes a code and a note of at least 10 characters. One code now covers every reason for asking (one's own nginx update asked for it twice, and a code is used only once). The browser test checks the field.
- After an upgrade, a tab restored from the browser's cache, or one that signed in again, ran the older program without offering a reload (it compared the server's version with what the server said when the tab loaded). The program now carries its own version and offers the reload at once; the page itself is never stored in the browser's cache.
- Alerts: the source names "Threat intelligence", "nginx updates" and "Country lists" were shown as their keys. A new nginx security alert for the same nginx version replaces the open one instead of standing beside it.
- Layout: the nginx advisories are aligned columns (in use first, then by severity); in Settings, the explanation of a switch uses the whole row instead of a narrow column.

## 0.4.99 (2026-11-19)

- Threat intelligence, distribution packages: Debian and Ubuntu backport security fixes without changing the upstream version (libbrotli1 1.0.9-2+deb12u1 carries the fix for CVE-2026-111497, which upstream fixed in 1.0.10), so the upstream number of such a package no longer decides "affected". The installed package's own change log (/usr/share/doc/<package>/changelog.Debian.gz, on this host; nothing is downloaded) is read: when it names the CVE, the threat is set aside with the package as the reason and its open alert is handled. A distribution's version whose package or change log cannot be found here takes the "check" path ("check the distribution's security advisory") instead of the urgent one. Reported by jt-wazuh-mgr.
- A threat set aside during a search (NVD's version ranges, a distribution's fix, nginx's advisories) no longer raises an alert in the same search.
- nginx security advisories with "Severity: none" (nginx.org lists one for every version) are no longer counted as open issues: the alert and the nginx updates page no longer say the next version does not fix everything because of it.

## 0.4.98 (2026-11-19)

- nginx's own security advisories: flaws in nginx itself (HTTP/2, HTTP/3, the resolver, the mail and stream modules) happen before ModSecurity sees a request, so no rule can refuse them. The nginx update job now reads nginx.org's security advisories with each run, compares them with the installed nginx and with the features this configuration uses (HTTP/2, HTTP/3, resolver, mail, stream, PROXY protocol, ssl_preread, SSI, alias, TLS session ticket keys), and raises an "nginx security update" alert (critical for a major advisory in a feature in use) saying that rules cannot help and whether the fixed nginx is ready. The verified update is proposed as a change by itself; an administrator still approves it with a one-time code. Threat intelligence entries for nginx are decided by the advisories (a version that is already fixed is set aside). The nginx updates page lists the advisories that apply.
- HTTP/2 or HTTP/3 off for a while: until the fixed nginx is installed, the nginx updates page can switch HTTP/2 or HTTP/3 off (and back on). Each edited line is marked with the change number and keeps its original, so switching back on restores it exactly; the root program plans the edit again itself, checks that nothing else changed, runs nginx -t, reloads, runs the health checks and puts everything back on any failure. With "Switch HTTP/2 or HTTP/3 off by itself for a major advisory" (Settings → nginx updates, on by default) a major advisory in a feature in use switches it off at once, and the update switches it back on.
- The nginx update check runs every 6 hours (was daily), with apt's lists for nginx's repository refreshed first by a short root job (jt-waf-mgr-nginx-aptrefresh.service; only the source lists that name nginx's repositories, signatures checked by apt as always), so a security release is seen the same day. "Check now" refreshes them too.
- deploy/build-modsecurity-module.sh: `MODSECURITY_PREFIX=/usr/local/modsecurity-<version>` builds the module against a libmodsecurity built from source (for security fixes the distribution has not shipped yet); the module finds it there.
- CrowdSec rules are no longer applied twice: proposing a rule that a change still on its way already adds (also inside a bundle from the CrowdSec page) is refused with that change's number, a bundle cannot add the same rule twice, and the check of a change refuses a result with the same rule in force twice. A rule already in force twice shows both copies on the CrowdSec page, with a button to remove one.
- Threat intelligence: when NVD's analysis names only other products (for example a browser for a library's CVE, or a vendor's own server for a web application's), the threat is marked "probably attributed to the wrong product" and no longer takes the urgent path; its alert says so.

## 0.4.97 (2026-11-18)

- Threat intelligence: a distribution package's version (`3.0.9-1+deb12u2`, `1.30.6-1~bookworm`, `2.9.14+dfsg-1.3~deb12u6`) is compared by its upstream release; outside every NVD range it does not affect this site, inside one it stays undecided with a note that the distribution may have backported the fix. Only the product itself is compared (another product of the same vendor, such as a desktop client, is no longer taken for ours). On production, 0.4.96 set aside one threat (CVE-2026-73570, Zimbra 10.1.20); most others had distribution versions.

## 0.4.96 (2026-11-18)

- Threat intelligence, fewer false alarms: NVD's affected versions (the CPE ranges of each CVE) are compared with the known version of our software. When NVD names the product and our version is outside every range, the threat does not affect this site, whatever the model guessed: it is set aside with the ranges as the reason and its open alert is handled (for example CVE-2025-48700: Zimbra 10.1.0 to 10.1.3, this site 10.1.20). Inside a range changes nothing by itself (preconditions may still apply); an unknown or unparseable version, or a patch level NVD lists separately, stays "unknown". Threats already open are compared at the next search, or now with `jt-waf-mgr intel versions --as USER`. The threat details show NVD's ranges.
- Filters: a dropdown set to a value has a "×" back to "all".
- War room: "other" in the site heat map opens the events of every Host no site serves (the new events filter `host=_other`), not all events.
- Layout: the module upload on the nginx updates page shows buttons, not the browser's file boxes (a UI check now refuses a visible native file input); the IP reputation lists show their last run and online sources on one line, a list switched off without a count; the CRS card lists its details first and the offline upload in a section of its own.

## 0.4.95 (2026-11-18)

- Sandbox: the "same request from inside" check of an external-only confident block no longer fails when rules already in place refuse that request from inside (internal protection, the CRS score, another confident block): such a request is run through the configuration as it is, and only the change's own rule matching it is a failure (reported by jt-waf-mgr's integration with jt-wazuh-mgr; the guard block was refused for the same reason).
- README and the project site: when jt-waf-mgr fits and when it does not, with measured limits (the evidence check reads about 10,000 log lines a second for 15 minutes; the collector stores about 750 events a second on one core; single-node only); the project site also introduces IP reputation, with a screenshot.

## 0.4.94 (2026-11-18)

- IP reputation: the IP lookup now says whether an outside address is known to be malicious, with the reasons -- this site's own evidence (blocks, confident rules, probing for secret files), public lists downloaded once a day and matched on the host (Spamhaus DROP, abuse.ch Feodo, FireHOL level 1, Emerging Threats compromised, CINS Army, blocklist.de, Tor exit nodes), Shodan InternetDB and your own MISP. The verdict is "malicious", "suspicious" or "no record" (never "safe"); the hover card shows it too. Nothing is blocked by itself.
- MISP: attributes/restSearch for the one address (read only, no context fetched); since most IP attributes come from feeds, an event weighs by the feed it comes from (for example FireHOL level 1 or a C2 list high, IPsum level 1-2 or scanner lists information). A self-signed MISP certificate is pinned by its SHA-256 fingerprint.
- The evidence check of a bundle of path rules works each log line out once per kind of rule (0.4.93's two views of the path made a bundle of 19 rules run out of time on 7 million lines).
- Only the new jt-waf-mgr-iprep.service connects out (hourly timer, and when a person opens an address; API tokens read what is there and never make it send); the web service never does. Online answers are kept 24 hours (an error one hour); only outside addresses, never the internal networks, at most 500 a day; a run stops after 7 minutes and leaves a failing source alone. Without a certificate check a pinned fingerprint is required, or the MISP key is not sent. Settings → IP reputation: off by default, lists chosen one by one, MISP address and key (write-only).

## 0.4.93 (2026-11-18)

- Path rules and an encoded "?": libmodsecurity 3.0.9 (Debian 12) cuts REQUEST_FILENAME at an encoded "?" (%3F) in the path, while the backend gets the whole path, so a path rule could be passed by, for example, putting "x%3F/../" in front of the path. A confident block on the path now also looks at the raw path up to the query (captured in the rule), normalised; its exceptions apply only when both views of the path are exempt, and are normalised too ("/static/../x" is no "/static/" path any more). An exclusion or a redaction scoped to a path is normalised and never applies to a path with an encoded "?". Tested on a real nginx + ModSecurity, Debian 12 (3.0.9) and Ubuntu 26.04 (3.0.14).
- Rules written by an older version: the managed rules page shows how many rules this version would write differently from the same settings, and "Write them again" proposes them as changes (proposed by the program, with the test requests the rules came with; checked and approved as any change, no setting changed). Also on the API (`GET /managed/outdated`, `POST /managed/regenerate`) and the CLI (`changes outdated`, `changes regenerate`). This also brings existing redaction rules the CrowdSec rules' fields.
- CrowdSec rules whose attack puts an encoded "?" in the path can now be converted (their path condition sees the raw path too): 215 rules can be proposed, all refusing their own attack requests on Debian 12 and Ubuntu 26.04. The rule list is read again at the next sync.
- Threat intelligence: a link with a space or a line break in it (written by the model) ended the whole run; it is escaped now, and a page that cannot be read only gives the model an error.
- Rules entered as text (adopted ones among them) that look at REQUEST_FILENAME cannot be written again: the managed rules page lists how many and offers a confident block on the new `raw_uri` target (the request target as sent) that refuses an encoded "?" followed by "../" in the path. On production logs (7.3 million lines) no request had that shape.
- Writing rules again is proposed on behalf of the person who asked, who cannot approve it alone, and only by people (not API tokens). An exclusion or redaction scoped to a path needs it both as sent and normalised (never wider than before). A rule switched on again is written by this version.
- CrowdSec page: tick several rules and apply them at once, as one change (up to 8 rules each; each goes to the sites of its software, a cross-application rule with none to all sites).
- The project site's script did not run since 0.4.90 (an apostrophe in an English text): buttons had no text and the language did not switch. Fixed, and every release now opens the site in a browser in all three languages (`tools/check_pages.cjs`).

## 0.4.92 (2026-11-18)

- CrowdSec rules are "cross-application" or "one application": a flaw of a framework, library, language or a generic weakness (React2Shell, Spring4Shell, PHP2Shell, Laravel, Django, exposed .env and .git files...) reaches every application built on it. The page has a "Cross-application" filter, and "related to this site" also follows the technologies the sites' software is built on (Nextcloud runs on PHP, Zulip on Python and Django; a technology can be entered in the software list too).
- A cross-application rule can be applied to all sites (when not every backend's stack is known): no site condition; the sandbox still sends the hub's attack requests and the recent requests of all sites; a person always approves, it is never applied by itself.
- More rules can be proposed: the hub's tests may name requests the rule must let through (answered 404, 405, 200), nuclei's random helpers and nested calls, callback addresses, variables naming each other, a path of `{{BaseURL}}` alone, several request groups in one template, `@timeout` annotations and an empty User-Agent. The hub's URI_FULL now maps to the undecoded REQUEST_URI_RAW, as upstream (PHP CGI's "?%ad" did not match). On a real nginx + ModSecurity + CRS 4.30, Debian 12 and Ubuntu 26.04: all 213 rules refuse their own attack requests (177 in 0.4.90), no request to let through matches, ordinary requests pass. The rule list is read again at the next sync.
- Threat intelligence gives the model the languages and frameworks each product is built on and looks for flaws in them too.
- API: a field of the wrong type (such as `host` as a string instead of `{"mode": "exact", "value": ...}`) is 422 naming the field; it was 500.

## 0.4.91 (2026-11-18)

- The sandbox sometimes missed the rules matched by the last request: nginx writes the audit record after the response has gone out and the sandbox read it too early (about one run in four in a test). A refused request then showed no matched rules, and a CrowdSec rule failed "refused by its own rule". The sandbox now waits until every refused request has its record and the file has stopped growing (at most 2 seconds).
- CrowdSec page: when the rule list was synced by an older version (no upstream tests yet) the page says to sync first; the "In use" column shows an "Apply" button for every rule that can be proposed, and the reason for those without tests. The upload hint is in plain words (a large file is uploaded in small pieces automatically) and says that the upstream tests are read too.

## 0.4.90 (2026-11-18)

- CrowdSec virtual patching rules can now be applied (phase 2): on the CrowdSec page a converted rule is proposed for the sites you choose (preselected: the sites of the confirmed software it names), from outside only or from all sources except the known scanners. It is an ordinary change: checked, run in the sandbox, approved by a person. The rule file, its hash, the commit and the licence come from the synced rules, never from the request; the rule text keeps the hub's file and is converted again at every check. Each rule takes its own range of ids in 10400–10999 (one per "or" branch) and is written before the rule that adds the critical score, so CRS's blocking evaluation refuses the request.
- The sync now also takes the hub's own tests (`.appsec-tests`, about 0.2 MB) and turns each nuclei template into requests the sandbox can send exactly (raw requests, paths, headers, a binary body); only templates judged by a 403 answer are taken. A rule is proposed only with such a test, and in the sandbox each of the hub's attack requests must be refused by that rule itself (not by another rule or the site), while the sites' recent requests must not be.
- Tested in a real nginx + ModSecurity + OWASP CRS 4.30 sandbox with every convertible rule of the hub that has a test: 177 of 177 refused their own attack requests and none of the ordinary requests, on Debian 12 (libmodsecurity 3.0.9) and Ubuntu 26.04 (3.0.14). Found on the way and fixed in the conversion: libmodsecurity 3.0 puts the arguments of a JSON body in ARGS but not ARGS_POST (body conditions now look at the JSON arguments there too); a value ending in "%" makes the whole configuration fail to load (not converted); ModSecurity cuts the path at an encoded "?" (%3F), so a rule whose attack does that is listed as not supported.
- Rules in use show when the hub changed them (propose the update) or removed them (propose the removal); the rules list names CrowdSec as their author; the sandbox results mark the hub's attack requests.
- Threat intelligence (phase 3): an open threat whose CVE has a convertible CrowdSec rule with a test gets that rule proposed for the product's sites, before any rule written by the model. For a vulnerability exploited in the wild that affects confirmed software, it may be applied at once (Settings: apply.auto_tighten_intel, as for the other virtual patches), from outside only and only when the hub's file does not warn about false positives; otherwise a person approves.

## 0.4.89 (2026-11-18)

- nginx updates, approved by an admin: once a module passed with the next nginx, the nginx updates page proposes the update as a change; approving it takes an admin's one-time code and a note. The apply program checks again as root: the module's SHA-256, both the new and the current package against the SHA-256 in apt's signed index (files the service user downloaded are not trusted for themselves), and the module once more with the new nginx. A dedicated unit, jt-waf-mgr-nginxswap (no network), then puts the module in place, installs the package with `dpkg -i` and upgrades nginx live (no interruption); the new master must run the new program, `nginx -t` must pass and the health URLs must answer as before, else the previous module and package go back. nginx is held again afterwards.
- Finishing an interrupted update: when nginx was updated and the module left behind (the old program still running, `nginx -t` failing, the next restart would fail), upload a module for the installed nginx; once it passes, propose finishing the update (module in place, live upgrade).
- Hold nginx button (apt-mark hold by the apply program).
- A module is used only once root trusts it: done by itself when the build script runs as root on the host; for a module built elsewhere, put the file on the host and run `sudo jt-waf-mgr nginx-module-trust FILE --sha256 <SHA-256 from the build output>`. Root copies the module into its own directory, checks the SHA-256 and uses only that copy for the update; root's re-test of the module runs as nobody.
- Only a single nginx package is supported (nginx.org packages); with packaged modules, or an nginx that needs other packages of the same version (Debian's nginx-common), the page shows packaging not supported.
- `build-modsecurity-module.sh` takes a package version (such as 1.30.7-1~bookworm).

## 0.4.88 (2026-11-18)

- nginx updates verified before they happen (new page Admin → nginx updates): when a newer nginx is available and the ModSecurity module is built by hand, a separate background job (jt-waf-mgr-nginxup, daily or on request) downloads the new nginx package (not installed), unpacks it, loads the waiting new module into that nginx on a local port and checks that a test request is refused (403) and an ordinary one passes (200); only then it shows ready to update. Packaged modules are tried at their new versions too; other modules built by hand are reported.
- The new module is uploaded by an admin (in parts; SHA-256, ELF format and the module.json description are checked). The release includes `deploy/build-modsecurity-module.sh`, which builds only the module (seconds) on the same system: nginx from the repository's source package, the ModSecurity-nginx connector pinned by version and SHA-256.
- The health check nginx_module adds `update_ready`.
- Rules page: CrowdSec virtual patching rules are listed on the CrowdSec page until one is applied.
- Next: holding nginx and an approved nginx update (only with a verified module, live upgrade, automatic rollback).

## 0.4.87 (2026-11-17)

- CrowdSec virtual patching rules: the rule column is wide enough for the names; "this site's software" compares only the rule's product and name, no longer the description that may mention other software in passing (a Wing FTP rule that mentions Lua).
- CRS: without gpg on the host the error says to `apt install gpg`, and the system check warns (no CRS release signature can be checked without it).

## 0.4.86 (2026-11-17)

- Sandbox: in the ModSecurity files copied into the sandbox (the main file, files whose audit log settings are rewritten), settings that name another file by a relative path (`SecUnicodeMapFile unicode.mapping 20127`, `Include`, `SecGeoLookupDb`, and the data files of `@pmFromFile` / `@ipMatchFromFile`) were looked up in the sandbox directory and failed; they are now made absolute against the directory of the original file, with no change to the configuration. Tested with nginx + ModSecurity on Ubuntu 26.04: the sandbox starts and both rules reading relative data files refuse as they should. (GitHub issue #1)

## 0.4.85 (2026-11-17)

- nginx and the ModSecurity module (so an nginx update never takes the WAF away):
  - Every 6 hours the production load_module modules are loaded once with a throwaway configuration (`nginx -t` as the service user, never the production configuration) to see that the installed nginx loads them; a module that does not load is a critical alert.
  - From the package lists apt already has (nothing downloaded): when nginx has a newer version but the ModSecurity module package wants another nginx-abi, or the module is built by hand and nginx is not held, an alert says so with the `apt-mark hold` way out. Debian / Ubuntu only; elsewhere it says it cannot tell.
  - The system check has "nginx and the ModSecurity module"; the health API has `nginx_module` (seen by the LibreNMS plugin).
- CrowdSec virtual patching rules: the page shows a running sync and refreshes by itself; four files at a time (about half a minute for a first sync); a sync started by an upload never reaches the internet while the sync is off; with several uploads waiting the newest is read; a zip's entry count is checked before its directory is read; YAML values starting with "- " are refused; space between the source card's buttons and the fields above.
- CRS uploads: the upload folder is renamed to a private one first; an upload arriving meanwhile waits for the next run.

## 0.4.84 (2026-11-17)

- CrowdSec virtual patching rules (Rules → CrowdSec virtual patches, phase 1: review):
  - The appsec rules and the LICENSE of one commit of crowdsecurity/hub on GitHub (MIT licence, about 0.2 MB) are read and converted into ModSecurity rules on this host, by their own job jt-waf-mgr-hub once a day (switched on in Settings; nothing is fetched again while the commit is the same) or with "Sync now"; the web service never reaches the internet.
  - Only rules whose conditions keep their exact meaning are converted ("and" as a chain, "or" as several rules); the others are listed as "not supported yet" with the reason, and a rule never loses part of its conditions. Of the hub's 243 rules today, 230 convert, all checked with `nginx -t` on nginx + ModSecurity.
  - Stat tiles, the rules that name this site's software (the confirmed list of threat intelligence), what is new or changed; each rule shows the upstream text and the converted rule. The MIT licence of the same commit is kept and can be shown.
  - A host that cannot reach the internet can upload a hub archive (GitHub's "Download ZIP" or a tar.gz); only appsec-rules and LICENSE are read.
  - Proposing a rule as a change for the sites comes in the next version.
- Offline CRS: a host that cannot reach GitHub can upload the release and its .asc signature on the CRS page; it is checked against the CRS release key and staged, then compared in the sandbox and approved as usual.
- Hub rule files are read only by the built-in restricted YAML reader: ambiguous forms, overlong lines and deep nesting are refused, never guessed; every converted line must have a fixed shape, and names and descriptions keep only safe characters.
- Uploads are sent in parts (the web service and nginx take requests of up to 1 MB) and checked for size and SHA-256; the web service only stores the file, the jobs unpack and verify it.

## 0.4.83 (2026-11-17)

- Health API: an engine set to detection only with rules that switch blocking on for what they match (confident blocks, the score refusal for outside sources) is fine ("blocking through rules"), no longer "detection only: nothing is blocked".
- Tests: every system path of a test configuration (the apply spool, the managed rule files, the IP block list, the database...) points at a temporary directory, with a test that checks it. A test wrote an IP block list request into the default spool: when the unit tests ran as root on a production host (release gate G10), its block list was replaced by the test entries for about a minute until put back.
- API tokens: the "Close" button of the new-token box keeps its distance from the token field.

## 0.4.82 (2026-11-17)

- Pause the WAF (troubleshooting, Admin → Pause the WAF): when a site misbehaves, stop refusing on every site or on one site for a while to see whether the WAF causes it. 1, 3, 12 or 24 hours or until resumed (a daily reminder while it lasts); it ends by itself. "Resume everything" removes only the pause; every other rule stays as it was.
  - While paused: this system's confident blocks, country limits and other own rules do not run; CRS only detects and still logs events; exclusions and masking stay. The IP block list and nginx's own limits stay in force.
  - Pausing takes an administrator, a fresh one-time code and a reason; approvers can resume. API tokens cannot pause, and ordinary changes cannot touch the pause rules. In effect in about a second (no sandbox run, no second person), each time a version like any change; "paused" / "resumed" is logged and notified once in force, a failure gets an urgent notification.
  - One site is matched by the site nginx chose (the ModSecurity transaction id `$host-$request_id`), which a full URL in the request line cannot hide; without that setting, the Host header, with a warning on the page.
  - A red band with the time left on every page; the health API reports a warning; other changes are tested in the sandbox as without the pause; a rollback leaves the pause as it is.
- An apply result that cannot be recorded marks the change as failed with an urgent notification (it no longer stays "applying", holding every later change).
- Only the pause rules may use `ctl:ruleEngine=DetectionOnly`; no other rule may take their ids or go above them; a rule-removal range (e.g. `10200-19999`) that covers the system score-refusal rules is refused.
- The run history charts of the event analysis share the row; the time axis no longer repeats a date.

## 0.4.81 (2026-11-17)

- A failed event analysis says why and keeps a detailed error log: the cause and what to do for each kind of error (502/503/504, unreachable, timeout, key refused, model missing, malformed answer, token limit...), and every try can be opened: time, batch, HTTP status, server headers and the start of the answer (the API key is always masked). Database schema 17.
- Token charts: the event analysis and threat intelligence pages show the tokens used per day for 30 days (the analysis page split into scheduled analysis and single-event AI analysis).
- Stat tiles at the top of the rule list: rules, on, partly off, off, not in effect, rules hit in 30 days and their hits (for the source chosen).
- The "Sites" column of the rule list keeps a readable width; site names no longer wrap a letter at a time.
- The event analysis status card in two groups (analysis and LLM, schedule and thresholds), laid out like the threat intelligence page; the rule page has a card title and two groups.
- Table columns whose values open the right-click menu show a small funnel by the heading, and the cell shows it under the pointer.
- The "formatted / raw" switch and the "Copy" button of a rule's text have the same height.

## 0.4.80 (2026-11-17)

- New `GET /api/v1/health` (API token scope `status:read`): whether the WAF works, for a monitoring system. Always 200; `status` is `ok`, `warning` or `critical`. It checks the nginx master process, ModSecurity in blocking mode, managed rule files changed outside jt-waf-mgr, the last apply, the event collector still reading the audit log, the IP block list loaded, program integrity, the audit chain, outside configuration changes in the last 24 hours and repeated event analysis failures, plus numbers for graphs. It uses the results the background checks keep and is cheap to ask every minute. The LibreNMS / Nagios plugin `check_jt_waf_mgr` (jt-lnms-plugins) reads it.
- The rule list opens on all sources (it opened on the site rules only, so OWASP CRS seemed missing); "All sources" is first in the source menu.

## 0.4.79 (2026-11-17)

- Token limits for the first-tier LLM as well: Settings → first-tier LLM has a daily and a monthly token limit for the scheduled event analysis and the single-event AI analysis together, 0 (no limit) by default. When one is used up the scheduled analysis uses the program rules only (outside probes for secret or configuration files still get confident blocks proposed) and single-event AI analysis answers "limit reached", until the next day or month; a limit used up during a run leaves the rest of the candidates unjudged that time. The event analysis page shows today's and this month's use.

## 0.4.78 (2026-11-17)

- Sandbox: when nginx loads dynamic modules with a relative path (the Debian and Ubuntu package default, e.g. `load_module modules/ndk_http_module.so;`), the sandbox looked for them in its own temporary directory and could not start, so every change, CRS installation and CRS update "failed the sandbox test". Relative paths are now made absolute with the prefix nginx was built with (`--prefix` in `nginx -V`); the configuration does not need changing. The configuration fingerprint uses the same absolute paths. (GitHub issue #1)

## 0.4.77 (2026-11-17)

- Event analysis: when the local LLM server (or a gateway in front of it) answers 502, 503 or 504 or cannot be reached for a moment, the batch is tried again after 20 and then 60 seconds, up to 3 tries (before: one immediate retry); while waiting, the progress shows when the next try comes. A try that failed only after a long wait (a timeout) is not repeated.
- A scheduled run that failed only on such a passing error, right after a run that worked, no longer sends the "Event analysis failed" notification (the run still records the error); two failures in a row, other errors and runs someone asked for are still told at once.

## 0.4.76 (2026-11-16)

- Threat intelligence, the software list: about 50 more applications tell their version by themselves (Jira,
  Confluence, Bitbucket, SonarQube, Nexus, Portainer, Immich, Jellyfin, Emby, Plex, Paperless-ngx, Graylog, Zabbix,
  Netdata, Prometheus, Alertmanager, Loki, InfluxDB, Elasticsearch / OpenSearch, CouchDB, Traefik, Nginx Proxy
  Manager, Discourse, Ghost, MediaWiki, Gotify, Roundcube, ONLYOFFICE, Element, Miniflux, Vikunja, Mealie,
  Audiobookshelf, Ollama, JupyterHub, MLflow, Metabase, Kubernetes, Rancher, Vault, Argo CD, NetBox, TheHive, Seq,
  Node-RED, Vaultwarden, Kibana, OpenSearch Dashboards, Solr): 67 in all. A version can be read in parts, from a
  header of any answer, and Roundcube's number is turned into its version.
- A site that lets only the local network in answers 403 to 127.0.0.1: the version is asked once more at this host's
  own local address. (The web service's systemd limits allow localhost only, so from "Guess again" this second try
  may not get through; the threat intelligence's own run does it.)
- The guess also reads each site's home page (its title, a generator tag, a header only it sends; over this host's
  own nginx, a few at a time): about 80 applications are recognised that way (Grafana, Open WebUI, WordPress, draw.io,
  Univention and more), so their versions are read too.
- The software list says why each guess was made ("Seen in the logs: site 5,844 requests" or "the home page of site
  names it"), with a note on what the numbers mean.
- Events: "Site answered 404 (nothing served)": a refusing rule matched but the site's own nginx answered 404 first
  (for example a `return 404` for hidden files such as .git and .env), so it was only logged. Its own label, a note,
  and a choice in the outcome filter, like the redirected ones.
- `settings export` always writes to a new mode-600 file (`-o FILE`); nothing goes to the terminal.

## 0.4.75 (2026-11-16)

- Threat intelligence: one product can be listed more than once (two Zimbra servers on different versions), each
  entry with its own sites (a site in one entry only). The search sees one line per product with every version
  ("10.1.20, 10.1.21") and counts it as affected when any of them is; never the sites. A refused entry says why under
  the form, and the sites field says how to give several (commas or spaces). Database schema 16.
- Threat intelligence: an opened threat reads better: the summary first, then three panels (versions and the fix with
  the version here, the attack and the precaution rule, exploitation with the full conditions), the sources as one
  line each, the buttons at the end.
- System check: lists show one chip per item (a long one opens with "N more"), long values break only at / - _ . and
  never inside a word, times stay on one line; "generated_at" has a name.
- Changes: the "approve the selected" row lines up (check box, note, button at the end).
- Temporary IP blocks: the "Sites tried" heading explains ×N (the address's WAF events on that site in the 7 days up to
  the block); a table heading can carry such a note.

## 0.4.74 (2026-11-16)

- Threat intelligence alerts are worded in the notification and interface language: an alert keeps the CVE, the
  software, its version and whether it affects this site, and the message and the Alerts page build the sentence from
  them (the English sentence stays in the audit trail and the log records). A version the model gave as "unknown" is
  no version: the alert says the version here is not known instead of "Zimbra unknown", and no "remove the rule"
  reminder comes from it.
- Threat intelligence: the "Guess again" button shows a spinner while it works; the page speaks of web applications
  rather than software.
- Notifications: clearer wording for "affects the version here"; full-width colon in the Japanese threat title.
- uninstall.sh removes every jt-waf-mgr unit that is installed (before, the CRS updater's units were left behind);
  `--purge` also removes the apply program's state and the upgrade backups.
- Release checks: a fresh install, uninstall keeping the data, reinstall and `--purge` leaving nothing behind are now
  part of every release test.
- `settings export --secrets` writes keys and passwords only to a new mode-600 file (`-o FILE`), never to the
  terminal. The site version check uses TLS 1.2 or newer, like every other TLS client of the program (code scanning).

## 0.4.73 (2026-11-16)

- War room: no demo banner taking a row; in demo mode the top bar's button is the sign (amber, filled, "Demo on" with
  a pulsing dot; its tooltip says the board is made-up data, a click leaves the demo); a link clicked in demo mode says
  so for a moment at the top right. The event intensity card is on the map page only: on the other pages their main
  card takes its row (the globe is much larger). The globe's controls are a column of icons on its right edge (names
  and keys in the tooltips), and the globe itself is a little larger.

## 0.4.72 (2026-11-16)

- Threat intelligence: the versions of the applications behind the sites are read from the applications themselves
  before each search (one request through this host's nginx, the certificate checked): Nextcloud, Zulip, Odoo,
  Grafana, Open WebUI, WordPress and draw.io (checked on running installations), and ownCloud Infinite Scale, Gitea /
  Forgejo, Rocket.Chat, Mattermost, Jenkins, Matrix (Synapse), Seafile, Harbor, Mastodon, Collabora Online and
  LibreNMS (with its API token, a new write-only setting). A version a person typed is never replaced; one read before
  follows upgrades (audited). The threat intelligence page and the project site (How it works → Versions) list which
  applications tell their version and how to read the others on their host. Univention Corporate Server is now
  recognised in the access logs.
- Threat intelligence page: the second-tier card shows two panels of one width, the structured sources as on / off
  badges; when one is off, a link opens Settings → Second-tier LLM (threat intelligence) (the hint named a card that
  does not exist).
- Security policy: from this release on, every exploitable issue fixed in a release gets a GitHub Security Advisory
  (SECURITY.md).

## 0.4.71 (2026-11-16)

- War room: the sixth page is named "AI analysis and threat intel" (in Chinese, AI 分析與威脅情報).

## 0.4.70 (2026-11-16)

- Wording: the interface no longer says "we" or "us". In Chinese the place the war room marks is 本站 ("our site"),
  and the threat intelligence says "affects our site" (影響本站); the English war room says "Our site" and "Center
  on our site". The Chinese word for "we" is now rejected by the interface wording check.

## 0.4.69 (2026-11-16)

- War room: a "center on us" button under the globe (key C) turns it to our location and stops its spin; the globe's
  buttons have one height and some room between them; the time range also offers the last 1, 5 and 10 minutes; in
  demo mode the demo button is the state as well (one place says "demo"); the globe no longer flashes when other cards
  refresh (its canvas is only reset when its size really changes, and painted again at once); in demo mode new
  latest events are pushed in at the top instead of the whole list changing every minute.
- `jt-waf-mgr check`: whether the service can read the audit log, when a directory open only to the service's group
  hides the file from the command line, is told by when the service last read it (`audit_log_last_read`; `null` when
  that cannot tell, not a problem). 0.4.68 reported such a host as a problem.
- Release checks: the ZAP scan has a home directory and proxy port of its own (another scan on the host stopped it).

## 0.4.68 (2026-11-16)

- ModSecurity guide (three languages), after an outside review: what jt-waf-mgr may change in nginx (marked includes
  for a site's WAF and the blocked page, the IP block list); `apt install --no-install-recommends` (the connector
  recommends the distribution's CRS 3); package sources and the loaded configuration checked with `apt-cache policy`
  and `nginx -T`; the upstream ModSecurity version without the distribution's revision; comments on their own lines;
  the raw audit log may hold what the database masks; `adm` is only an example (install.sh finds the group); base
  rules can log before the CRS; a hand-installed CRS in `crs-<version>` (so jt-waf-mgr can update and roll it back);
  the optional site rule files commented out until created; testing with the real site name and a value of this
  request; reload after switching to `On`.
- A comment at the end of a ModSecurity directive line (`SecRuleEngine DetectionOnly  # ...`) is no longer read as part
  of its value (libmodsecurity ignores it).
- `jt-waf-mgr check` adds the main file(s) nginx loads (`main_config`), the audit log path, the audit-format warnings
  and `problems` in words; it exits 1 when any is found. Whether the service can read the audit log is judged by the
  groups systemd gives it (the command line runs without them).
- README and project site: a disclaimer at the end.

## 0.4.67 (2026-11-16)

- Threat intelligence: only web-facing software is followed (the web servers, the WAF and the libraries it parses
  requests with, TLS, the CRS, web applications). What an older version guessed outside that (an SSH server, the
  system's Python) leaves the list even when confirmed, its open threats are set aside and their alerts handled: a
  WAF cannot shield what is not reached through the sites. A person's own entries stay.
- War room globe: zoom with the mouse wheel, two fingers or the buttons (0.6x to 3x); a drag let go while moving
  keeps turning at that speed and slows down; up to 60 frames a second when the machine keeps up; the globe marks
  our place without words. The map area is larger (four latest events, the timeline fills its card, a slightly
  larger globe). The map subtitle reads "Outside sources → our WAF". The state, the range and the buttons at the
  top have the same height. `?page=globe` (or another page) opens the board on that page.
- Wording: the decision "fallback" is now 標記後封鎖 in Chinese (a rule marked the request, the last rule blocks).
- Project site: the top picture rotates through the dashboard, the war room and the request volume (arrows, dots
  and arrow keys switch by hand); the screenshot grid has an even number (the war room globe added); thumbnails are
  full-size lossless WebP (small text was blurred).
- War room, more: a switch in the top bar shows the blocked events alone or with the logged ones (`?only=blocked`,
  key B; the server counts them so); keys like jt-ipam's board (1–7, arrows, PgUp / PgDn, Home, Space, R, Z, B, D,
  F, + − 0, S) with an H button and panel listing them; rankings, site rows and the score-only list slide to their
  new places, numbers roll, bars grow and shrink smoothly, a new minute slides the timeline left; pages change with a
  short slide and fade; the threat-intelligence list is in columns; a proper full-screen icon; on screens narrower
  than 1400 px the top bar's buttons show icons only (one line).
- Threat intelligence page: the second-tier card is two aligned groups (model and search, structured sources).
- The help menu says "Project site".
- Installing: one fixed place, `/opt/jt-waf-mgr-install/current` (every release unpacks there; install, upgrade,
  rollback and removal run there); the README and the project site download the release from GitHub, verify and
  unpack it there, and list where things are after installing (the program stays in `/usr/lib/jt-waf-mgr`). The
  site fills the version into its commands; the release checks catch an old version in the README commands.
- The date fields of the filters stay on one line (the full value in the tooltip).
- Project site, how it works: the enlarged diagram fills the window and zooms (+ − fit, Ctrl+wheel, drag to move).

## 0.4.66 (2026-11-16)

- War room: a time range in the top bar: live (the last 30 minutes, as before) or the last 15 minutes, 1, 3, 6, 12 or
  24 hours, 7 days. Kept in the address (`?range=24h`) so a wall screen can open it directly; new events keep coming in
  every 5 seconds. The timeline and the site cells keep their number of steps, each covering more time.
- War room: the big numbers roll when they change: down when they grew, up when they shrank (only the digits that
  changed; no motion for viewers who asked for less).
- War room: the maps and the globe mark where we are as "Us" (Settings > War room: latitude and longitude; the name is
  now optional and shows as "Us · name").
- War room: demo mode (a button at the top, or `?demo=1`): made-up traffic of sites under steady attack, with waves from
  one country now and then, on every page (maps, flow, sites, review, AI and threat intelligence, alerts and changes).
  It is made in the browser: nothing is read from or written to the server, a striped banner says "demo" the whole
  time, the state shows "Demo", and links do not open. For showing the board without real data.

## 0.4.65 (2026-11-16)

Fixes from a review of the last versions:

- Settings: switching the second-tier provider could bring back a saved API key together with a new server address
  typed in the same save, sending the key to that server. A stored or brought-back key now always needs entering
  again for a different server, also through the import and the command line.
- War room: only names a site serves are shown (internal-only sites keep their alias); any other Host (a trailing
  dot, an address, a wildcard match, a name an outsider sent) shows as "other". One snapshot is computed at a time
  for all screens. After a database restore the wall starts over instead of waiting for higher event ids.
- Carried approvals: only when the change's own added and removed lines are exactly those approved, by a person who
  may still approve, never for one's own change.
- Threat intelligence: KEV, OSV and NVD trouble (a cut download, an odd answer, a full disk) leaves that source out
  of the run instead of failing it. A threat that becomes urgent later (its preconditions confirmed) raises the
  alert then.
- Settings import: the preview never compares a key or password with the file.
- Command line: `settings export -o` only creates a new file (mode 600); `settings set` keeps text as typed (digits in
  an id or a password stay text) and says when the web service needs a restart; a missing id is a clear error.

## 0.4.64 (2026-11-16)

- Threat intelligence: NVD scores (Settings > threat intelligence, off until switched on). After each search the
  intelligence job asks the NVD API for the CVSS score and weakness (CWE) of each CVE found -- only the CVE id is
  sent, one request every 6 seconds, at most 20 a run, answers kept 7 days. The official severity replaces the
  model's guess (both are kept); the intelligence page shows "NVD 9.8 · CWE-78" under the severity.
- The war room in README and on the site now shows arcs to an entry point (synthetic destination in the test data).

## 0.4.63 (2026-11-16)

- Threat intelligence: OSV queries (Settings > threat intelligence, off until switched on). Once a day the
  intelligence job asks osv.dev's query API which known vulnerabilities affect the exact Debian / Ubuntu package
  versions of the confirmed software (source package, installed version and release are sent; no bulk download;
  answers kept a day). They are given to the model as a hint, with a reminder that a distribution may patch without
  changing the upstream version.

## 0.4.62 (2026-11-16)

- Threat intelligence: the CISA Known Exploited Vulnerabilities catalog as a structured source (Settings > threat
  intelligence, off until switched on). Once a day the intelligence job downloads it from cisa.gov (about 1.5 MB),
  checks it is the catalog and replaces its copy only then. A vulnerability in it counts as exploited in the wild
  (noted as the evidence), and its entries for the confirmed software are given to the model to check against our
  versions. The intelligence page shows the catalog's size and date.

## 0.4.61 (2026-11-16)

- War room: on a narrow screen the page tabs stay on one line and scroll sideways (seven tabs no longer take half the
  phone screen).
- README and the project site show the war room.

## 0.4.60 (2026-11-16)

- Event list: an attack flood is one row. The same request (source, site, method, path, rules, outcome) again within
  a minute folds into the row of its newest event, marked "×n" with the time span; a switch above the list shows
  every event again (remembered in this browser). Only the list folds: every count, chart, analysis and check still
  counts each event.
- Second-tier LLM: Google Gemini as a provider, through Google's OpenAI-compatible endpoint (the URL can stay empty;
  a Google AI Studio key and a model are needed); it searches through the MCP server.

## 0.4.59 (2026-11-16)

- War room, third stage: the last two pages. AI and threat intelligence: the latest event analysis (events looked at,
  candidates, the model's answers by kind, proposals, how long) and the threat intelligence (open threats, exploited
  ones, what affects us, what a virtual patch covers, software waiting for a person). Alerts and changes: open alerts,
  changes being checked, waiting for approval and applied in the last 24 hours, as cards that open in a new tab.
  Ids, kinds, states and times only: no path, reason or summary text on the wall. Nothing on the board starts an
  analysis or writes anything. All seven pages of the design are in.
- API: `GET /warroom/ops` (viewer).

## 0.4.58 (2026-11-16)

- War room, second stage: three more pages. Decision flow: bands from source (outside / inside) through what decided
  (confident rule, fallback refusal, CRS score, other rule, logged only) to the outcome, one event counted once; a band
  or a node opens those events. Site activity: each site's events in 2-minute cells over the 30 minutes, with blocked
  and logged, where the events concentrate, and the focus sites that had none. False-positive review: what the CRS
  score alone blocked, by site, and the internal and outside logged-only events to look at, each a link to the event
  list with the same window. Rotation goes through all five pages.

## 0.4.57 (2026-11-16)

- Administration from the command line: `jt-waf-mgr blocks | alerts | changes | settings | tokens | intel | review`,
  the same rules as the web interface. A write names the person (`--as`, an existing account with the role needed);
  the audit trail records that person with `cli` as the source; approving one's own change, or a loosening one, asks
  for what the web interface asks (single-admin mode, `--totp`). `--json` for machine-readable output.
- Settings export and import (Settings > Export and import settings, or `jt-waf-mgr settings export / import`): one
  JSON file with every setting of the settings page and the change workflow's. Keys and passwords only with a fresh
  one-time code (the file says so). Import shows the file next to the current values (only those that differ by
  default), you tick settings, whole groups or all, and only those are written -- all or none, with a one-time code,
  each audited, plus one "settings imported" record.
- Several tightening changes approved at once: tick them on Changes > Pending approval (or "all"), one click; each
  under the same rules as one by one. A loosening change is still approved on its own page.
- An approval carries over: a tightening change approved while another one was being applied is checked again
  against the new version and, unchanged and passing, applied without a second click (audited as carried).
- Configuration text (nginx lines, the fail2ban example, nginx -t output, sandbox messages, settings values) gets
  syntax colours; the UI check asks for it.

## 0.4.56 (2026-11-16)

- War room, first stage: Overview > War room opens a board of its own in a new tab, for a wall screen (dark, no admin
  menu). Two pages: a flat world map and a 3D globe you can turn, with the same numbers: the last 30 minutes per source
  country (events, blocked / logged, different sources), events a minute, the latest events; a tracer for each new
  batch, from the country to your WAF's location (Settings > War room; without it only the sources are drawn).
  Rotate, pause the animation, freeze the data, full screen; arrow keys switch pages, Space pauses, Esc closes a
  country's details. It tells live, quiet, not collecting, disconnected and catching up apart. Read only.
- The board's API (`GET /warroom/snapshot`, `GET /warroom/events?after=`) leaves out the source address, the path, the
  query and the headers; a site nginx serves only to internal networks gets an alias. Spec: docs/spec/WARROOM.md.

## 0.4.55 (2026-11-16)

- Filter and exclude everywhere: a right-click on a value in any table opens the value menu (filter by / exclude this
  value for that table, shown as chips above it; copy; open a link in a new tab). The menu's first row shows the value
  and what it is. Traffic: a site can be excluded too (`not_host`).
- Help is a menu: user guide, product website, how it works, API manual, changelog, report a problem, source code.
- Number tiles look like the dashboard's on every page (IP lookup with a 7- and 30-day trend, CRS, WAF model, periodic
  review); the UI check rejects plain tiles. The role next to your name is an icon (its name in the tooltip).
- Event AI analysis: the steps as they happen (queued, started, gathering, asking the LLM with the time waited,
  checking) with a spinner; the LLM server and model used; a 502/503/504 from the server is retried once; failures
  explained. Every "loading" has a spinner.
- Event detail: a card title and facts in aligned rows. Periodic review: focus sites in a table. Long values (site
  patterns in the rules list, nginx lines in country limits, the request column of the events) stay inside their
  column with "..." and the full text on hover.
- Sites: "outside requests, 7 days" says what it counts (every request from outside, any country, answered or not),
  and for a site under a country limit how many of them the country rule blocked.
- IP blocks: the sites each address went for before it was blocked; the places the list does not cover are a table,
  and an `internal` location (the blocked page, error pages) is no longer listed. Locations marked `internal` no
  longer count as skipping the WAF either.
- Threat intelligence: a vulnerability's preconditions (a C library, a build or configuration option such as sshd
  without PAM) are compared with a few host facts sent with the software list (operating system, architecture,
  C library, sshd's UsePAM): not met means not affected; not confirmed means a warning to check instead of the urgent
  path. A version match alone no longer raises a critical alert.
- Software guess: ActiveSync alone is Z-Push (not where Exchange, Zimbra, SOGo or Kerio answer it); LibreNMS from its
  API; Zulip no longer from `/api/v1/events`.
- Architecture diagrams (user guide and website) show the second-tier LLM, the access logs, the download services and
  their sources; "Admins + tokens". Wazuh active response: an example script that blocks through the API
  (deploy/wazuh/active-response). Each GitHub Release carries the SBOM as its own file; the website links to it.
- Wording: zh-TW uses 加強 and 被外部修改, denylist / allowlist terms in every language (preflight and the i18n check
  refuse the old ones); every audit action has its name in all three languages (checked).

## 0.4.54 (2026-11-15)

- Large traffic: the dashboard reads hourly counts kept by SQLite triggers (by site, origin, outcome, decision,
  attack type, rule and source) plus the partial hours at both ends from the events themselves: the same numbers,
  without scanning every event of the window (synthetic 400,000 events: 7 days 6.0 s -> 0.95 s, 24 hours 0.96 s ->
  0.34 s; the more concentrated the traffic, the larger the gain). The upgrade counts the stored events in (schema 15).
- One dashboard answer is shared by every screen for 15 seconds (or while no new event arrives, up to a minute).
- systemd: the web service runs below nginx (Nice 5, CPU and IO weight 50) and the background jobs lower still
  (Nice 10, weight 20): a busy host serves the sites first; an idle one sees no difference.
- Software guess: host packages limited to web-facing software (the web stack, other web servers, PHP / Node.js /
  Java, web applications installed as packages: about 50 products; glibc, bash, git, mail and database servers and
  the like are no longer guessed). Zimbra is also recognised from its sign-in page (a monitoring check sees only that).

## 0.4.53 (2026-11-15)

- Confirmations use the app's own dialog (the page's colours and language; delete / revoke in red, starting on
  "cancel"; Esc or a click outside cancels) instead of the browser's; the UI check rejects window.confirm / alert /
  prompt.
- Sites > Blocked page: "Preview" opens the page in a new tab with a sample request id, site and time (its own
  sandboxed policy: only its inline style, by hash).
- Second-tier LLM: switching provider saves at once and keeps each provider's server, API key and model (the key on
  the server only): switching back brings them back. "Test connection" next to the model tests the LLM only; the MCP
  server has its own button.
- Software guess: a guessed entry renamed by a person (Exchange -> Z-Push) is not guessed again; Exchange is no
  longer guessed from ActiveSync alone (Z-Push, Zimbra and others answer it too).
- Navigation: "Overview" is a menu; the current overview is its "Dashboard" (a live war-room board will join it).
- Overview and traffic: the range buttons are as tall as the site picker. Settings > Country lists: the four facts
  side by side, the lists in use as a table of their own.
- Chinese interface and documents: full-width semicolon, comma and colon in Chinese text, a space after a half-width
  ")" followed by a word (the i18n check rejects the old forms).
- README and project site: the three ways to use it (nginx as the web server, as a reverse proxy, or both on one
  host), with a diagram; the site's threat intelligence card now says the second tier writes its own virtual
  patches.

## 0.4.52 (2026-11-15)

- Software guess: about 300 applications instead of 43 (identity, mail and groupware, files and documents, chat,
  CMS and shops, ERP / CRM / service desk, development, monitoring and security, virtualisation, storage, network
  and VPN gateways, application servers, home and media), plus PHP / ASP.NET / Java / ColdFusion as a last resort;
  about 160 host products instead of 11 (glibc, OpenSSH, web, database, mail, DNS and VPN servers, container
  runtimes, ...; versioned package names such as php8.2-fpm or postgresql-15 included).
- The signatures moved to a data file (jtwafmgr/data/software-signatures.json); each carries sample paths, and a
  test checks that every sample is guessed as its application and that common paths (/api/status, /dashboard/,
  /assets/index-*.js, ...) are guessed as nothing. Too-wide signatures found that way were narrowed (Uptime Kuma no
  longer matches any Vite site's /assets/index-*.js; Proxmox Backup Server is no longer hidden by Proxmox VE).

## 0.4.51 (2026-11-15)

- Software guess: Zulip's API (/api/v1/messages and the like) is no longer taken for Rocket.Chat (its signature
  now has to match a whole path segment); the same for Mattermost.
- A guessed entry you remove stays removed: "Guess again" leaves it out (adding the name by hand takes it back).

## 0.4.50 (2026-11-15)

- Second-tier LLM settings: the API key comes before the model (the model list needs the key), as on the first tier.
- The provider's own web search also works with OpenAI's own API (Responses API web search, plus the program's own
  page reader so "exploited" still needs a CISA page read in that run). Other OpenAI-compatible servers: use MCP.
- MCP search server: its own "Test connection" button (no LLM needed): it answers and offers web_search.
- Software list: "Confirm all"; the guess counts 2xx answers only (a redirect is no sign of an application) and
  skips jt-waf-mgr's own site; guesses no longer made and never confirmed are removed. A name is enough (version
  optional).
- A product confirmed by name only: an exploited vulnerability in it counts as possibly affecting you (critical alert,
  urgent virtual patch -- still checked like every change).

## 0.4.49 (2026-11-15)

- Settings: the two LLM cards are named the same way and sit next to each other: "First-tier LLM (event analysis)",
  then "Second-tier LLM (threat intelligence)", then the scheduled event analysis.

## 0.4.48 (2026-11-15)

Fixes from GitHub code scanning (CodeQL):
- Every TLS client of the program (health checks, syslog over TLS, notifications, e-mail, the threat intelligence
  fetches) refuses anything older than TLS 1.2.
- Response headers: a CR or LF in a header value is removed before it is sent (no value comes from a request today;
  this keeps it so).
- preflight finds inline scripts and styles in the built page with an HTML parser instead of a pattern (upper case,
  odd spacing).

## 0.4.47 (2026-11-15)

- Threat intelligence settings: "Test connection" and a model list, like the first tier. The intel service does the test
  (the web service never connects out): the models offered, a one-word answer, and the MCP search tool. Works before
  the search is switched on.
- Value menu (like Graylog): a right-click on a value, or its small funnel icon, opens "Filter by this value",
  "Exclude this value", "Copy value" (and "Open" where there is a page). The value itself now opens its page (an
  address opens the IP lookup, a rule ID the rule page) instead of filtering. Exclusions show as chips and are sent as
  `not_<name>` (event list and overview APIs). The address card no longer covers the menu or a tooltip.
- Settings: the local LLM card is now "First-tier LLM (self-hosted)"; it serves the scheduled event analysis and the
  "AI analysis" button on an event (the text said only the former).
- Chinese text: a space before a half-width "(" after a word (checked by the i18n check).

## 0.4.46 (2026-11-15)

- Blocked page: also shown to addresses on the IP block list (the page's internal location allows everyone; before,
  nginx refused the page too and showed its own 403). Checked with real nginx and ModSecurity.
- Blocked page: the snippet and the page are jt-waf-mgr's own files: a release with newer ones offers "Update the
  page" on the Sites page (a change), instead of refusing them as edited by hand.

## 0.4.45 (2026-11-15)

- Sites: "Blocked page" -- the page blocked visitors see (three languages, with the request id to paste into "Someone
  was blocked?"), on every site at once or one site at a time, as a change a person approves: one marked include line
  per server block that serves content (blocks that only redirect or have their own 403 page are left alone); the root
  program writes the page and the snippet next to the managed rule files, nginx -t, reload, health checks, and puts
  everything back if a step fails. Replaces the sample in `deploy/blocked-page/`.
- Settings: the "Threat intelligence (second-tier LLM)" and "Periodic WAF review" cards were missing from the settings
  page (the "Settings" button on the threat intelligence page led nowhere). The build check now fails when a settings
  card is not shown on any page.
- Menu on narrow screens: the page behind is dimmed, each group is its own card with a coloured heading, and the
  current page is marked with a bar.

## 0.4.44 (2026-11-15)

- Overview: one line with the latest periodic WAF review (its verdict, blocked / logged) and a link to it.

## 0.4.43 (2026-11-15)

Fixes from an independent security review of the threat intelligence and the AI analysis:
- Rule patterns: a ModSecurity macro (`%{...}`) or a POSIX class (`[[:alnum:]]`) is refused in every rule's regex --
  ModSecurity and the Python checks would read them differently. Virtual patches get the same checks as every rule.
- "Exploited in the wild" counts only when the search read it on a CISA page in that run (else "said to be
  exploited", not urgent); urgent patches past the daily limit: at most 5 a day.
- Tokens: counted after every response, the run stops when the day's or month's limit is reached, and a run that
  fails half way (or with an unexpected error) records its end, its error and its tokens.
- fetch_url: port 443 only; the name is resolved once and that checked address is the one connected to (no second
  lookup); NAT64, IPv4-mapped and 6to4 addresses are refused.
- A threat is matched to a confirmed product by the same name or whole words (no more "nginx" matching the
  ModSecurity-nginx connector).
- Virtual patches always carry a sandbox test (on the product's site, else on a site the WAF serves; header patches
  send the header).
- Software list: a host name from the logs must be a valid name; a person's site list is kept when guessing again.
- Threat references show their site first; the event AI analysis warns when the LLM server is not on the local network.

## 0.4.42 (2026-11-15)

- System check: threat intelligence (set up, searched recently, within its token limits, a confirmed software list, no
  open exploited vulnerability that affects you).
- README and project site: screenshots of the threat intelligence and periodic review pages.

## 0.4.41 (2026-11-15)

- "Someone was blocked?" also takes nginx's 32-digit request id alone (an error page can show it); API
  `GET /events?request_id=`.
- `deploy/blocked-page/`: a page for blocked visitors in three languages with the request id, and the nginx snippet to
  use it (optional; jt-waf-mgr never writes it).

## 0.4.40 (2026-11-15)

- "Someone was blocked?" on the Events page: paste their IP address (opens the address lookup), the URL they opened
  (the site's blocked events on that path) or a request id (that one event). API: `GET /events?unique_id=`.

## 0.4.39 (2026-11-15)

- "Configuration changed outside" no longer fires when one apply wrote the managed rules and the IP block list in
  the same minute (each file is checked on its own).
- Switch the WAF on for a site from the Sites page (and off again): a change. Checks: the plan (each of the site's
  server blocks without ModSecurity, not redirect-only, none with a hand-written `modsecurity off;`) and, switching on,
  the site's recent normal requests from the access logs replayed in the sandbox with ModSecurity on. A person approves
  (switching off is a loosening). The root apply program computes the plan again, requires the same blocks and the
  same file contents as checked, adds one marked include line after each `server {` line (the snippet the other sites
  use to switch ModSecurity on, else a managed one), runs nginx -t, reloads, checks the health URLs and puts the files
  back on any failure; switching off removes exactly that line. These edits are not reported as outside changes.
- Change pages name CRS and site switches properly.

## 0.4.38 (2026-11-15)

- AI analysis of one event: a button on every event page sends the event with what is around it (the same source in
  the hour around it and over 30 days, the same site and path over 7 days with internal users and answers, the rules it
  hit) to the first-tier (local) LLM, which answers attack / false positive / unclear, how sure, why, and one piece of
  advice (block the address, block this kind of request, a narrow exclusion, watch, nothing). The advice is checked
  (an internal address is never offered for blocking; an action that does not fit the verdict becomes "watch"), and
  its buttons open the usual forms (the IP block form filled in, a proposed confident block or exclusion from the
  event). The analysis job answers it (jt-waf-mgr-analyst.path); the web service never talks to the LLM. API
  `GET` / `POST /events/{id}/analysis`.
- The IP block form can be filled in from a link (address and reason).

## 0.4.37 (2026-11-15)

- Threat intelligence writes virtual patches: for a vulnerability seen in the URL or a header (open, affects or may
  affect a confirmed version, exploited or critical / high), the second-tier LLM gives a narrow match with attack and
  normal examples; the program checks it (anchored, no slow patterns, matches its attack examples, matches none of
  the normal ones, the regression samples or common header values) and proposes an ordinary confident block, limited to
  the product's site when there is one, outside sources only, with 403 tests. Applied automatically like the event
  analysis's blocks (Settings > Change workflow, on by default); one for a vulnerability exploited in the wild that
  affects you is not held by the daily limit. A critical alert asks a person when no rule could be written or its checks
  failed. When a person updates the software to another version, an alert says the patch may be removed.
- Periodic WAF review: only outside attacks the site answered with content (2xx) are listed as not refused; probes
  answered 4xx and requests that only got a redirect (a plain-HTTP block that answers 301 before ModSecurity runs) are
  counted apart.
- Wording (zh-TW): 加強 instead of 收緊 (the check refuses the old word).

## 0.4.36 (2026-11-15)

- Threat intelligence (Events > Threat intelligence; off until switched on in Settings): a second-tier LLM -- any
  OpenAI-compatible server (left empty: the event analysis's local server) or Anthropic (Claude Messages API) --
  searches the web every few hours for new vulnerabilities in the software list, above all those exploited in the
  wild. The program guesses the list (this host's packages from the package database, the CRS version, the
  applications the sites answer for in the access logs); a person confirms it, and only product names and versions
  are sent. Local models search through an MCP server (web_search, e.g. SearXNG) and read pages with fetch_url (https
  only, an allow-list of domains, public addresses only, plain text); with Anthropic the provider's own web search and
  fetch can be used. The answer must fit a JSON schema; a threat is kept only for a confirmed product, with a CVE or
  GHSA id and https references. An exploited vulnerability that affects the confirmed version raises a critical
  alert; new ones are notified. Token limits per day and month. Its own sandboxed unit (jt-waf-mgr-intel: hourly
  timer, "search now"); the web service never talks to the LLM or the web. Virtual patches from the findings come
  next.
- Periodic WAF review: probes answered 4xx by the site are counted, not listed as attacks that got through; a
  secret or backup file name, or a source trying many paths, is not a possible false block.
- Tables open a row in place; the notification matrix has a select-all box per channel; every condition in the
  overview's filter banner has an x; "Open this page" buttons name the page ("Go to Rules").

## 0.4.35 (2026-11-14)

- New logo: a square split by an inspection gap, with the request held at the gap (no shield; readable at 16 px).
- Periodic WAF review (Events > WAF reviews; every 3 hours by default, Settings > Periodic WAF review): requests
  blocked by the CRS score alone grouped by site and path, with possible false blocks (an internal user, or no attack
  type) first; new internal hits; outside attacks that were only logged; what was done automatically (event analysis,
  changes, IP blocks); what waits for a person; one line per focus site (events, login paths, answers 429, a source
  logging in again and again). Stored, and sent through the notification channels (event "Periodic WAF review": the
  first focus site every time, the others only when something needs a look). Read-only; never request content or
  query strings. API `GET /reviews`, `GET /reviews/{id}`, `POST /reviews/run`.
- System check: twelve more items -- ModSecurity and CRS settings, background jobs (every timer and path unit
  enabled), CRS updates, event analysis, IP blocks, country lists, the DNS check, health check URLs, changes waiting
  or stuck, API tokens expiring or unused, request counts, and whether the audit log is rotated.
- Outside configuration changes: "Files" opens right under its row instead of at the end of the page (tables can
  now open a row in place).
- CRS page: the version card has a summary line (version, state, last check, check now) and a tidier list.
- Overview: the custom range buttons have the same height as the date fields; event list: the method and the path
  are aligned.
- Ubuntu 26.04 (Python 3.14): installed and tested; each request thread now closes its database connection, and a
  deprecated call was fixed.

## 0.4.34 (2026-11-14)

- The DNS job's folder defaults to "dns" next to the database (`[dns] dir` still overrides it), and the web service
  writes there only when the database's folder exists: a test with a temporary database (the release checks run the
  tests as root on the server) can no longer write into the system's folder, as one did with documentation addresses.

## 0.4.33 (2026-11-14)

- DNS check (Settings): enter internal and external DNS servers (several of each); a separate restricted job
  (jt-waf-mgr-dns, every 15 minutes, "check now") asks each of them about every site name nginx serves, detects a
  wildcard record, and the Sites and Country limits pages show what DNS knows of each site. A name only internal DNS
  knows on a site nginx lets anyone into is shown in red: hiding a name keeps no one out.
- PTR names: the same job looks up the PTR name of outside addresses (recent events, blocks, any address the pointer
  rests on) and checks it forward. The card shown when the pointer rests on an address (events, the overview, blocks,
  event details) gives its PTR name, where it is, whether it is blocked and what it did in the last 7 days.
- The sandbox runs regression samples the change refuses through the configuration in place too: a sample the rules
  in place already refuse no longer fails a change.
- The author shown for rules this system generates is "jt-rules" (the API value is still `jason_tools`).
- Project site and README: integrations (Wazuh, jt-wazuh-mgr, Graylog, other SIEM, fail2ban, chat and webhooks); a
  GitHub link in the top bar; "Home" on the architecture page; "Upstream open source" for the parts other projects
  write.

## 0.4.32 (2026-11-14)

- IP blocks: an approver can extend an active block (a new end counted from now, up to the interface maximum, with a
  reason); an admin can make a block permanent, from the list or the form (it never ends by itself; a person ends it).
  A token or a rule never sets a permanent block, and blocking the same address again never shortens one. Each
  blocked address shows its country.
- Countries without a GeoIP database: the registries' lists of the country blocks give the country of an outside
  address on every page (events, blocks, the country filter).
- Automatic blocking of sources that guess secret files also counts requests answered with a redirect although a
  confident-block rule matched (a site that redirects every path answers before the WAF can refuse; nothing is
  served). It is on by default for new installations (it acts once IP blocks are on). Such events show "redirected
  (nothing served)" and the outcome filter picks them out.
- Tooltips: one tooltip in the site's style everywhere (light and dark, keyboard focus, Escape); the browser's own
  never shows. Everything that can be clicked shows the pointing hand. Negative actions (switch off, delete, end a
  block, reject) are red; the build refuses one that is not.
- Request volume: the tiles are the overview's (change against the same length of time before, the trend, a link
  from the WAF blocks to their events).
- Country limits page: the rule id on the same line as the countries, the refusing countries as named chips, the time
  of the last refusal (it showed 1970). "Help" in the menu. The log destination's choices are chips with room between
  them.

## 0.4.31 (2026-11-14)

- Sites page: the country-limits column is one line per site (what its country rules allow or block) linking to
  that site on the country-limits page; the buttons, the changes on their way and the notes are on that page only.
  The country-limits page opens one site with `?host=`.
- Who can reach a site (Sites and Country limits pages): internal only, some countries, some addresses, a source
  check that is not understood, or inside and outside, from nginx's own checks for the whole server block (geo and
  map variables resolved), with the outside requests of the last 7 days. A name that only internal DNS knows is not
  protected by that alone: anyone who reaches the server can ask for it.
- A server block that only redirects (http to https) shows "redirect only" instead of "WAF off", and is counted
  apart.
- Configuration changed outside jt-waf-mgr: a change recorded before 0.4.30 shows the logins looked up in the host's
  authentication log when its page is opened, and says why what changed in the files is not shown.
- Top bar: theme, language, account and log out are the same height, and the account has a frame like the buttons.

## 0.4.30 (2026-11-14)

- Security: a rule limited to one site (a country limit, a block or an exclusion for a host) did not match the site's
  name with a trailing dot ("example.com."), which nginx serves as the same site, so such requests skipped it. New
  and changed rules match it (and a port). **Rules already applied keep the old text until they are changed: propose
  a "modify" with the same settings for each country rule (it counts as a tightening).** Country limits must name the
  site exactly.
- Known limit, documented: a request line with a full URL ("GET http://example.com/ HTTP/1.1") is routed by that URL
  whatever the Host header says, and nginx gives ModSecurity only the path, so no ModSecurity rule can tell which site
  it is for (HTTP/2 can do the same with :authority). Where a country limit must hold against such requests (a site
  reached directly, not through a CDN), keep a check in nginx (a geo variable and `return 403`) as well.
- Country limits by site (new page under Rules): every nginx site with the countries that may reach it or are
  blocked (names in the interface language), whether the WAF runs there, locations that skip it, nginx's own access
  limits, what the rules refused in the last 7 days and from where, the changes on their way, "modify", "switch off"
  and "add limit" (also for each name of a site that no rule covers yet). Rules and changes that match no site are
  listed apart. The Sites page has a country-limits column too, and the country list card says which countries and
  which sites each list file is for.
- Changing a country limit is a tightening when it covers the same site the same way and refuses at least what it
  refused before (fewer allowed countries, or more blocked ones) and exempts no new address; anything else is a
  loosening and needs a person. A country change is never applied automatically. The change form's preview shows the
  direction the change will get.
- A block by a country rule counts as a confident block (it was listed with the "CRS score only" blocks, the likely
  false positives); stored events are corrected once.
- Configuration changed outside jt-waf-mgr: the alert names the files and who was logged in to the host meanwhile
  (from the host's authentication log: account, source address, key or password, sudo commands); the change's page
  shows the logins and what changed in each file. File contents are stored with secret-looking values masked (new
  table, schema 10).
- The sandbox fails the check rather than leave out a site's samples when it has no address of an allowed country to
  send from, and never sends from an address the country rules always let through.
- Nothing private leaves: the pre-push check looks at every commit being pushed (its message, author and committer,
  every file it adds or changes against the PUBLISH.txt allowlist and the privacy scan, merges included) and every
  tag (message and tagger). Private networks, addresses at the end of a sentence, upper-case mailboxes, more key and
  token formats and UTF-16 text are detected; binary files other than PNG and WebP images are refused; the marker
  that allows an address on purpose never lets a private name or a key through; without the private denylist the
  hooks refuse instead of checking less. The release notes are scanned, and the tarball is checked against its
  checksum and scanned again, before anything is sent to GitHub. New tests (`tests/test_publication.py`) and a test
  plan section on what is published and what checks it.
- Layout: one accent line on cards (the status colour or the attention colour was a second line next to the title
  bar's), the CRS page's version and path and the update switch and its explanation no longer run together (and
  eight other places with the same lost space; the build refuses that pattern), the analysis timeline's ticks no
  longer cross its label, space between the registries table and the buttons below it. The browser test checks
  every page for a doubled line.

## 0.4.29 (2026-11-14)

- Country blocks: every sandbox request from outside now comes from an address that the country rules of its own site
  let through. Before, a change's regression samples all came from the country that change allows, so a Japan+Taiwan
  rule failed on the samples of a Taiwan-only site. Any change failed on the samples of a site with a country limit,
  because the usual test address is in no country. Tests written for a change get the same address, so a test that
  expects 403 is refused by the rule it tests, not by the country limit. A regression sample of a site that no outside
  address can reach is left out. CRS switches are compared the same way.

## 0.4.28 (2026-11-14)

- Country blocks: the sandbox's regression samples come from an address of an allowed country (the usual external test
  address is in no country, so every sample was refused and the check failed). The impact on the change also shows the
  last 7 days next to all logs kept: when nginx already has the same limit, the recent figures are what changes.

## 0.4.27 (2026-11-13)

- Country blocks (optional, off by default): limit a site to some countries ("only Taiwan and Japan") or block some
  countries. Each limit is a rule (new kind `country`) through the change workflow: the checks count from the access
  logs what it would have refused and how much of that was answered 2xx/3xx; the sandbox tests a request from an
  allowed country, from a refused one and from inside; it is never applied automatically. The internal networks, the
  known scanners, the trusted proxies and the protected list are never refused.
- The country lists come from the five regional Internet registries (APNIC, ARIN, RIPE NCC, LACNIC, AFRINIC):
  jt-waf-mgr-countries.service (new, sandboxed, daily while country blocks are on) checks every file against its MD5
  file and its own record counts and replaces the lists only when all five pass. The root apply program writes the
  lists ModSecurity reads (`/etc/nginx/modsec/jt-waf-mgr/countries/`), tests nginx and reloads, and puts everything
  back on failure; a list a rule still uses is never removed. Settings → Country blocks shows the lists and
  "Update now". API: `GET /countries`, `POST /countries/update`; sandbox tests may carry `src_ip`.
- Decision flowchart: a box shows two full lines of detail (the second line was cut); hover shows the whole text.
- After an upgrade the IP block list is written again once in the current format.

## 0.4.26 (2026-11-13)

From an independent review:
- Temporary IP blocks: the list file no longer ends in `allow all;`. nginx stops at the first allow / deny that matches
  within a level, so it switched off an administrator's own `deny` placed after the include in the same `http { }`
  (403 became 200, reproduced with nginx). The file now holds deny lines only; whether it is loaded at the http level
  is read from the include itself.
- A list that was written but whose reload failed is no longer reported as applied when it is sent again: the file
  goes back to what nginx runs, and the root program records what nginx loaded only after a reload succeeded.
- The root program also checks the protected networks, known scanners, internal networks and trusted proxies set in
  Settings (it read only config.toml before); a database it cannot read refuses the write.
- Automatic blocks of secret file scanners: only names that were refused or not found (4xx/5xx) count, at least one
  name must be unmistakable (.env, .git, keys, dumps, backups; a config.json alone never decides), and an address
  that got a 2xx/3xx for any such name is left to a person.
- First CRS installation in the sandbox: modsecurity.conf and the new CRS files go through the same audit log rewrite
  as everything else, so the candidate never writes the production audit log.
- CRS comparison counts any 4xx/5xx as refused (sites refusing with status 406 or 400), not 403 only.
- Tests that need a GPG test key are skipped where gpg cannot make one.
- Interface: the request volume page's site picker sits in the filter row; 「多擋/少擋」 became 「新增封鎖/不再封鎖」.
- The "how it works" page lists the three automations with their switches, including what the automatic IP block
  reads and when it holds back; request volume notes that sites sharing one combined log count under (default).

Also:
- Login page: after an upgrade the reload notice sits right above the login box, as wide as it (it used to stretch
  across the page with the button at the far right).
- Project site: more room between the menu entries; the three language buttons are one language button with a menu.
- LLM advice: Qwen 3.8 or later, Gemma 4 or later (older versions are not recommended); Llama dropped from the examples.
- The apply summary after a reload no longer says "old workers still draining after 0s" when it does not wait: it says
  how many old workers are still finishing open connections. Documents: a temporary IP block applies to new requests
  from the reload on; connections already open (WebSocket) last until they close.

## 0.4.25 (2026-11-13)

- Chinese interface and documents: 「封鎖」 everywhere instead of 「阻擋」 (the confident block is now 「確定封鎖」); the
  interface check refuses the old word.
- Program rules for the event analysis (no LLM needed): a secret or configuration file name asked for from outside
  only, never answered 2xx and not used internally is proposed as a confident block by the program itself; such
  candidates are no longer sent to the model. Without an LLM the analysis now still runs, with these rules only
  (`analyst.rules`, on by default; the Analysis page says which mode runs).
- Automatic temporary IP blocks for sources that guess secret files (off by default; Settings > Temporary IP blocks): one
  external address asking for 5 different secret or configuration file names within 60 minutes is blocked for 24 hours
  on every site; at most 30 such blocks an hour; an address a person unblocked is left alone for 7 days.
- "Configuration changed outside" no longer fires for jt-waf-mgr's own apply: files equal to a version that is written
  but not yet reported (the apply program waits for old nginx workers) are jt-waf-mgr's.
- Interface: the AI tag is readable in light mode; toggled buttons are solid; the change workflow settings are laid
  out in rows like the others; health check URLs can be picked from the sites nginx serves; a timeline shows the
  scheduled analysis (interval and window) as the values change; the GeoIP card's buttons are full size; long
  summaries no longer push a horizontal scrollbar into the change and alert lists; missing labels in the
  configuration card.
- Rule authors: a setting for who wrote the rules imported at adoption (the site, or Jason Tools when Jason Tools
  wrote them before adoption).
- Project site: an alerts section and the change list next to the workflow steps (synthetic data).
- Temporary IP blocks, how to connect: the Blocked IPs page has the steps and a ready fail2ban action (with this
  server's address filled in); the README has the same action, and the project site an "Optional: temporary IP
  blocks" install block.

## 0.4.24 (2026-11-13)

- Temporary IP blocks (optional, off until switched on): other systems block a single address for a while through
  the API (`POST /api/v1/blocks`, scope `blocks:write`; `DELETE /api/v1/blocks/{ip}` ends the token's own), approvers
  block addresses or ranges up to /24 or /64 on the new Blocked IPs page. The root apply program writes one nginx file
  of `deny` lines (at most once a minute, tested with nginx -t, the old file put back on failure) that the
  administrator includes once inside http { }; it covers every site, also those without ModSecurity. The page shows
  whether the file is really loaded and which servers or locations it does not reach. Defaults 24 hours, at most 7
  days from a token and 30 days by hand, 500 active, 200 per token, 60 new per token and hour; internal networks,
  known scanners, trusted proxies and a protected list (for example a CDN) are never blocked, checked again by the
  root program. Every add, extension, removal, refusal and expiry is audited (`block.*`). The IP lookup shows whether
  an address is blocked now.
- The project site lists what is inside and who wrote it: the WAF engine and detection rules (not ours, with their
  licences), jt-waf-mgr, the rules Jason Tools writes, bundled third-party code and optional outside data.

## 0.4.23 (2026-11-13)

- Request volume (Events > Request volume): every request in the nginx access logs counted per site and hour (2xx,
  3xx, 4xx, 5xx, 403, 444, 429, external, bytes) next to what the WAF blocked and logged, so the WAF numbers have a
  denominator. Numbers only: no address, URL or user agent is kept. The web service reads the live logs where it
  stopped (inode and offset, stored with the counts in one transaction), finishes a renamed file through its inode,
  re-reads one truncated in place, takes the site from the file name and caps the sites a forged Host header can
  create. On by default; switched off, and its optional alerts (a site at N times its usual hour, or many 5xx
  answers) set, under Settings > Request volume. API: `GET /api/v1/traffic`.
- The rule list shows who wrote each rule: OWASP CRS, an OWASP CRS plugin, a third-party plugin, ModSecurity base
  settings, Jason Tools (rules generated from a form and the Jason Tools rule pack) or this site (hand-written), with
  a filter and counts. API: `author` on `GET /api/v1/rules`.
- API manual for integrations (docs/API.md, three languages): tokens and scopes, errors, every endpoint a token can
  call with examples, and a script that proposes a confident block.
- Documentation: connecting to the management interface (port, the example vhost, TLS certificate options, first
  login); jt-waf-mgr installs the OWASP CRS itself (a new host needs only nginx and ModSecurity) and never writes nginx
  configuration; the recommended LLM for the event analysis; account recovery commands.
- Wazuh rule drafts: rules for a failed CRS signature and a staged CRS release; refusals now match `token.denied` too.

## 0.4.22 (2026-11-13)

- OWASP CRS updates, step 3: a host without the CRS. The check stages the newest 4.x release that has waited; the CRS
  page offers "compare in the sandbox and propose installing CRS <version>" (the same requests without and with the
  CRS). Once approved, the root program installs crs-<version> next to the main ModSecurity file, links crs to it,
  creates crs-setup.conf from its example when there is none and adds the two Includes right after modsecurity.conf;
  nginx -t, reload and health checks, and any failure takes everything out again. The ModSecurity installation guide
  mentions this way.

## 0.4.21 (2026-11-13)

- OWASP CRS updates, step 2: on the CRS page an approver proposes switching to the downloaded and verified release, or
  back to a version kept on the host. It is a change: the sandbox runs the same recent requests (and the regression
  samples) through the CRS in use and the other version and lists what is newly blocked or no longer blocked; a person
  other than the proposer approves (never automatic). The root program then reads the staged tarball without
  following links, checks its SHA-256 and the CRS signature again, unpacks it itself, refuses it unless its files are
  exactly the ones compared, points the crs link at crs-<version> (a plain crs directory becomes crs-<version> + link
  on the first switch), tests and reloads nginx, checks health and switches back on any failure. The three newest
  versions are kept. When applied, the "CRS update ready" alert closes. API: `POST /api/v1/crs/updates/propose`.

## 0.4.20 (2026-11-13)

- OWASP CRS updates, step 1 (off by default; Settings or the CRS page: "Keep the CRS current from here"): a new
  sandboxed unit, jt-waf-mgr-crs (daily, or "check now"), takes the newest release of the major version in use once
  it has been out `crs.wait_days` (7), downloads its minimal tarball and signature, keeps it only when the signature
  is valid and made by the pinned CRS release key (shipped inside the signed program), unpacks plain files only into
  a staging area with a manifest, and opens a "CRS update ready" alert. Nothing in nginx changes yet: comparing it
  in the sandbox and switching to it (approved by a person) come next. A bad signature is audited as critical.
- CRS page: "CRS versions and updates" with the version in use, the versions on the host, the newest release and
  when it can be used, the downloaded and verified one, and a warning when another program also updates the CRS.
- API: `GET /api/v1/crs/updates`, `POST /api/v1/crs/updates/check`; CLI: `jt-waf-mgr crs-update`.

## 0.4.19 (2026-11-13)

- Log servers (syslog / SIEM): up to 8 destinations, each with its own address, protocol (local socket, UDP, TCP,
  TLS), record format (JSON, CEF, LEEF 2.0, GELF 1.1, key=value), syslog header and content (audit records, WAF
  events, alerts), its own queue, retries and counters. WAF events and alerts can now be sent too. "Send a test"
  sends one sample record as entered and shows exactly what went out. Destination 1 keeps the existing settings.
  API: `GET /settings/syslog`, `POST /settings/syslog/test`; settings `syslog.payload`, `syslog.content`, `syslog.more`.
- Tables: drag a column header's edge (or use the arrow keys on it) to set its width, remembered per table; a double
  click sizes the columns automatically again. Long one-line text in a table ends in "..." (hover shows it all).
- Changes: a proposal of the event analysis is marked "AI event analysis"; an API token's proposal shows whose token
  it is and the address it came from. Long summaries are cut, a click unfolds them.
- Page headers: their buttons have one size.
- Project site and READMEs: an offline installation and upgrade guide (`docs/OFFLINE*.md`), log servers.

## 0.4.18 (2026-11-13)

- Rules list: tick rules (or "select all listed") and switch them off or on as one change; or switch a whole category
  (CRS: an attack type) off or on. CRS rules switched off need a scope: chosen sites (exclusions, picked from the nginx
  server names) or every site (an expert rule, admins only, marked high risk). A whole CRS category switched off can
  only be approved by an administrator, with a one-time code and a written reason. A preview shows the operations and
  every rule that cannot be switched here, with the reason. API: `POST /api/v1/rules/toggle`.
- Rule states: CRS's own mechanics (sampling, the localhost exceptions) no longer make every CRS rule look "off for
  some"; a rule above the paranoia level shows "not in effect" before any exclusion.
- Alerts: the analysis page has a "handle" button per alert; `/alerts?id=N` selects that alert and opens its form.
- Overview: the navigation shows its icon; the country list beside the map is one line per country, with the first ten.
- Settings: the configuration file section is a card with its own title.
- Project site and READMEs: a calmer security headline, accounts and sign-in (TOTP, lockout, password policy) and
  recovery on the host (`jt-waf-mgr user unlock | reset | passwd | disable | enable`).

## 0.4.17 (2026-11-13)

- Rules list and CRS page show whether each rule runs: on, off (removed for every request, with where), off for some
  (an exclusion for some sites or paths) or not in effect (a CRS rule above the paranoia level). Totals per state, a
  state filter, and per category (CRS: per attack type) how many rules are in each state; a click lists them.
  Managed rules that are switched off are listed too. API: `state`, `state_detail`, `family`, `summary`.
- Rules in the managed files are no longer marked "not managed" (the flag was never set).
- A folded card next to an open one keeps its own height.
- Event analysis: a false-positive candidate judged an attack (or unsure) shows "stays blocked" instead of "not
  proposed": the requests were already blocked and stay so.

## 0.4.16 (2026-11-13)

- Overview, by source address: internal / external and the country are a column of their own, aligned from row to row.
- Rules list: a long description is cut with "..." (the table no longer runs off the right edge); hover shows it
  all, a click unfolds it and a second click folds it again.

## 0.4.15 (2026-11-13)

- Event analysis: the verdict history a "false positive" must agree with counts only runs that had candidates (the last
  six within 14 days). Quiet runs, which have nothing to judge, pushed earlier verdicts out within hours.

## 0.4.14 (2026-11-13)

- Event analysis is harder to fool, after a small model called the same probes an attack, then a false positive,
  then an attack again in three runs:
  - blocked requests for names attackers look for (secrets, backups, credentials, deployment, cloud and CI files)
    from a few outside sources only, or from sources that also tried other paths, are reconnaissance by the program's
    own rule: never proposed as a false positive, never an alert, not sent to the model;
  - a path called an attack in one of the last six runs is not loosened on a "false positive" verdict ("unstable");
  - the model also sees how many paths the sources tried, the attack families they triggered elsewhere and whether the
    name is a sensitive one, with explicit guidance; the analysis asks with temperature 0.
- A disclaimer on the analysis page, in the analysis settings, the READMEs and the project site: AI can be wrong in
  both directions; loosening always needs a person, only tightening that passed every check applies on its own.
- Adoption works on a fresh ModSecurity: a side without a site rule file gets its managed file included right before
  the first / after the last CRS rules Include (the root program checks the anchor is a CRS rules Include of the main
  file and that nothing is included twice). Before, adoption failed without site files, and with only one of the two a
  managed file was written but never loaded. The page explains it, or links the installation guide when no main file
  loads the CRS rules.
- ModSecurity installation guide (`docs/MODSECURITY*.md`, three languages); Ubuntu 22.04's libmodsecurity package is
  too old (3.0.9 or later needed).
- Tests: the notification tests no longer depend on the time of day (from 8 o'clock on, the daily report added one
  message and five of them failed).

## 0.4.13 (2026-11-13)

- Tabs and segmented controls (changes, alerts and others) are as wide as their buttons instead of the whole row.
- The country map lists the first six countries beside it, with "show all"; the map stays in view while the long
  list scrolls. The overview's source address and network owner cards span the full width; an address shows
  internal / external and its country on the same line.
- An open page notices when the server was upgraded (every few minutes and when the tab comes back to the front) and
  offers a reload; until then it kept running the version it had loaded.
- Traditional Chinese: 「收編」 is now 「納管」 (adopting the rule files) everywhere; the i18n checks reject the old word.
- The UI check rejects HTML sinks (`v-html`, `innerHTML` and the like) in the front end.
- Project site: light theme in the logo's colours with a palette per card, sharp thumbnails (taken at twice the
  resolution by the browser test, `tools/make_thumbs.py`), screenshots open large in the page with a close button,
  separate install, upgrade and uninstall blocks with a copy button. READMEs: an Uninstall section.
- Test environment: the synthetic network name no longer contains markup (it showed up in screenshots).
- Settings, focus sites: the site names nginx serves are offered as one-click choices (with a search when there are
  many); typing names by hand still works.
- The guide link moves to the right of Admin in the top bar. The alerts page tabs use the same segmented style as
  the other pages. Event analysis: the alerts of a run line up in columns.

## 0.4.12 (2026-11-13)

- Event analysis no longer mistakes a scanner for users hit by a false positive. An outside address blocked on 5 or
  more different paths in the window is probing: its paths are skipped as "scanner" and not sent to the model.
  Found on real data, where one address probing `/env.bak`, `/settings.py.bak`, `/static/config.json`... produced
  false-positive alerts.
- A false positive seen from only one or two outside addresses (no internal user) gets neither an exclusion nor an
  alert (before, the exclusion was already withheld but the alert was still opened).

## 0.4.11 (2026-11-13)

- Overview: without a GeoIP database, the source list says that countries, networks and the world map appear once
  GeoIP is set up (with a link to the setting for administrators). `/overview` reports `geoip`.
- Tests close every file and test server.

## 0.4.10 (2026-11-13)

- Notification settings: "Preview" on every event of the event matrix shows the message it sends (title, text,
  facts, link), from made-up example data, in any of the three languages. `GET /notify/preview?event=&lang=` (admin).

## 0.4.9 (2026-11-13)

- Filter by country: click a country on the world map or in the country list (overview, event list), or pick one in
  the event list's filters. Works for the overview, the event list and its timeline (`country=` in the API, external
  sources placed by GeoIP).
- The address lookup map marks the location even when the address has no events in the last 30 days.

## 0.4.8 (2026-11-13)

- World map of where requests come from (GeoIP): on the overview (every country, with the top 15 listed beside
  it), on the event list (the loaded events) and on the address lookup (the address's location). Drawn in the
  page from a bundled outline (loaded only when needed); no map service, nothing leaves the browser.
- Event timelines over several days are labelled once per day, at midnight.
- System check: "CA file unreadable" and "unencrypted remote" show green when they are false; the CA line is shown
  only when a CA file is set.
- Notification and LLM calls close the connection after an HTTP error response.

## 0.4.7 (2026-11-13)

- Timelines on list pages are titled for what they count (alerts, changes, audit records, versions, deliveries,
  configuration changes); alerts use the status colours (critical red, warning amber).
- Chinese interface: "封鎖" throughout instead of the colloquial "擋".
- Event analysis: duration column shown as minutes and seconds; guidance boxes no longer drawn inside a second frame.
- Notification settings: channels that are off are clearly dimmed in the event matrix.
- Tests: every page is also checked in Japanese.

## 0.4.6 (2026-11-13)

- Alerts can be acted on: "Draft an exclusion" (false positive) or "Draft a block" (attack) opens the change form
  filled from a recent event of that site and path.
- A false-positive alert is marked handled by itself (audited, with the change number) when the exclusion proposed
  for it is applied. An attack that may have passed still needs a person.

## 0.4.5 (2026-11-13)

- Daily report through the notification channels at a set hour (default 08:00, -1 = none): events, blocks and
  logged-only requests against the previous 24 hours, external sources, busiest sites and most matched rules, open
  alerts, changes applied, analysis proposals.
- Overview: a notice with the number of open alerts (and critical ones) and a link to them.

## 0.4.4 (2026-11-13)

- The guide's architecture diagram shows the event analysis, the notifications, the LLM server and the channels.
- Five overview tiles fit one row on a tablet.
- The browser test checks phone (375 px) and tablet (768 px) widths: no page scrolls sideways, the menu reaches every
  page group; screenshots for a visual check.
- Test plan, test checklist and changelog also in Traditional Chinese and Japanese (preflight checks every changelog
  has the release).

## 0.4.3 (2026-11-13)

- READMEs and the project site show the interface in the reader's language (English, Traditional Chinese and
  Japanese screenshots, all from the synthetic test environment); the browser test checks the Japanese pages too.
- A local or UDP syslog destination that cannot be reached no longer leaves a socket open on every retry.
- API and test plan documents: event timeline, syslog settings and behaviour.

## 0.4.2 (2026-11-13)

- Syslog over TLS can trust a SIEM's own certificate authority: `[syslog] ca_file` in config.toml (root only,
  never in the web interface).
- Timelines on the configuration change history (by cause: jt-waf-mgr, automation, outside) and the versions.
- The analysis page says the timer checks every five minutes (not hourly).
- Fix (independent review): with syslog over TLS, a certificate or handshake error made 0.4.1 drop the queued
  records one by one; now every connection, name or TLS error waits and retries, and only a record the server
  cannot take (too large) is dropped. A failed TLS handshake no longer leaves its socket open. The system check
  warns about an unreadable CA file, unencrypted remote syslog and dropped records.

## 0.4.1 (2026-11-13)

- Syslog in the web interface (Settings): on / off, destination (the local /dev/log, recommended, or host:port),
  protocol UDP, TCP or TLS (server certificate checked against the system CAs), format RFC 3164 or RFC 5424 (ISO
  time, host name, message id; octet-counting framing over TCP), facility. A TCP / TLS server that does not answer is
  retried after 30 seconds instead of slowing every request; failures show in the system check.
- Teams messages: a web address in a value is never turned into a link.
- Tests clean up every temporary directory they create.
- The analysis unit and guide describe the LLM server as configured (not local) and the batched requests.
- Browser test environment: a synthetic analysis run, so the analysis page and its summary are covered.

## 0.4.0 (2026-11-12)

- Notifications: e-mail (SMTP, text + HTML), Telegram, Microsoft Teams (Workflows, Adaptive Card), Slack,
  Discord, Zulip, Nextcloud Talk (signed bot) and a generic webhook (JSON, HMAC-SHA256 signature, optional
  bearer token). Set up in Settings > Notifications with a "send a test" per channel; a matrix decides which
  events go to which channel (security and integrity, changes awaiting approval / applied / failed, event
  analysis, backups, version changes, accounts). Messages in Traditional Chinese, English or Japanese, with a
  link back to the page. The web service only queues them; a new sandboxed one-shot unit
  (jt-waf-mgr-notify: request file + one-minute timer) sends them, retries (1, 5, 15 minutes), records
  failures, limits each channel per hour and keeps 90 days of delivery records. Values from requests are
  never markup, mentions or links in a message; secrets are write-only and never in errors or the audit trail.
- Alerts to follow up: what the event analysis or the system finds that someone has to look at (an attack the
  site may have answered with content, users hit by a false positive, an attack in progress, outside
  configuration changes, integrity problems, failed applies or backups, attacks on one-time codes) opens an
  alert, listed under Alerts with a count in the menu, notified at once and reminded until an approver marks
  it handled with a note (audited).
- Event analysis: also looks at requests the anomaly score blocked and proposes the narrowest exclusion for a
  false positive (one site, one path or path prefix, the rules and request parts that matched); exclusions
  always wait for a person. Confident blocks proposed by the analysis can apply by themselves when the new
  workflow switch is on (same conditions as other automatic tightening: external sources only, clean
  evidence, sandbox passed, daily limit). An attack probe the site answered with 2xx opens a critical alert;
  the model may flag an attack in progress.
- Overview: drag across the hourly timeline to look at that time range, or pick a custom range (1 hour to 31
  days; days instead of hours beyond a week); external sources show their country and network owner.
- Every card title can be folded (button or a click on the title band), remembered per page; cards with
  buttons in the title get the title band too; card titles fit on phones.
- Fixes: chart tooltips are no longer squeezed or cut off inside small cards; a link to a settings card keeps
  it at the top while the cards above it load.
- System check: notifications (on, channels in use, failures, stuck queue); Wazuh rule drafts for alerts and
  failed notifications. Schema 7.
- Event analysis page: a summary of the latest run (events analysed, how long it took, candidates, verdicts,
  proposals, alerts, the model's main points); every run records the number of events analysed and its duration.
- Timelines with drag-to-select on the event list and the address lookup (from the server, same filters) and on
  the audit trail, alerts, notification deliveries and changes (from the loaded rows).
- Top bar grouped into drop-downs (events, rules, changes, admin) with the open-alert and pending-approval
  counts on their group.
- Rules show where they come from: OWASP CRS (version, registered automation), a CRS plugin, imported at
  adoption, a change by a person / an API token / the event analysis (with the change), a vhost, an unmanaged
  site file, the ModSecurity base settings.
- Audit trail: the raw action name and a readable one in the reader's language; details open in a dialog with
  syntax-coloured JSON.
- Filter forms: applied conditions in colour; changed but not applied ones marked and the Apply button asks to be
  pressed.
- Overview tiles: icon, label, number, trend line and a full-width trend chart at the bottom.
- Layout: system check cards (status colour, problems first, no stretched cards, missing labels translated),
  the WAF model's scoring card and the lists of uninspected sites / locations, centred table rows, the guide's
  diagram line no longer on the group border, separated badges.
- Wording: 「封鎖」 instead of 「擋下」 in Traditional Chinese; the LLM is "self-hosted" (地端), not "local" (本機).
- From the independent review: exclusions proposed by the analysis are one exact path written one way (no case,
  ./ or ../ variants) and plain request parts read only from ModSecurity's own text; none from one or two outside
  addresses; approving one needs a one-time code and a note; at most five alerts of a kind per run; chat
  messages can never mention people; webhook token and secret bound to the webhook address (scheme, host, port);
  no SMTP password without TLS; no loopback / link-local notification targets; one dead channel does not hold
  up the others; rollback stops the analysis and notification units while the database is restored; the names
  analyst, system and cli are reserved.

## 0.3.5 (2026-11-12)

- Settings cards: two-column rows (name, explanation and where the value comes from on the left, the control
  on the right), on/off switches, database choices as chips, short number fields, unsaved rows marked, the
  save result next to the buttons.
- Notices keep a clear gap to the text before and after them, on every page.
- Local LLM settings in a clear order (address and key, test, model, switch on) with a step diagram: one
  "Save and test connection" button, and the model is chosen from ONE list filled by the last test (the
  separate text field and second list are gone). Reasoning models (a <think> block before the answer) work
  for the test and the analysis.
- The analysis interval is set in minutes (at least 10); the timer wakes the job every 5 minutes. A value
  stored in hours by 0.3.4 is read as minutes.
- Analysis page: live progress while a run is asked for or running (each step as it happens, also after
  leaving the page and coming back), then the result.
- Rule texts with syntax highlighting and a formatted view (one action per line, chained rules indented), the
  exact original one click away, copy button; also in diffs, the change preview and managed rules.
- Database backups can be downloaded (admin, fresh one-time code each time, audited). The nightly backup is
  no longer skipped after a backup made by hand the evening before.
- Long lists: one way to page through them -- "next" past the loaded rows loads the next batch (the separate
  "load more" button is gone).
- Overview: focus sites with events get a full-width card each, quiet ones share one line; rules chart full
  width with readable labels; trend lines show the value at the pointer; horizontal bars keep each label next
  to its bar; the source column stays on one line.
- Settings: the read-only configuration list refreshes after a save and no longer repeats what is set in the
  web interface; links to a settings card scroll to it.
- Flows with descriptions are a vertical timeline; every card title has an icon; theme and language are one
  icon menu each; compliance values as a labelled grid; paths aligned; audit record opens into view.
- Wording: two-factor authentication (雙因素驗證); API token is 「API 權杖」 in Traditional Chinese.
- Security: a number beyond the database range in a query parameter (e.g. cursor) answered 500; now 400.
- From an independent review of the backup download and schedule: one-time codes for sensitive actions
  (backup download, approving one's own loosening) are limited to 5 wrong codes per 10 minutes (then refused,
  recorded as critical) and a code can never be used twice, also by two requests at once; the backup is
  sent in pieces (not read into memory) and checked against its recorded SHA-256; a failing nightly backup is
  retried hourly (three times) and never removes good copies; the newest three backups are always kept; the
  monitor's timers use a monotonic clock; Wazuh rule drafts for downloads and repeated wrong codes.
- Release gates: TEST_PLAN.md; a security scan of every route on every browser test run
  (tools/security_scan.py); an OWASP ZAP passive + active scan of a logged-in disposable instance
  (tools/zap_scan.py, accepted findings with reasons in deploy/zap-baseline.conf).
- Adoption is no longer recorded as an outside configuration change: the site's old rule files leaving
  main.conf are part of jt-waf-mgr's own change. (The record made at the first site's adoption stays as it
  is; the system check stops warning about it after 7 days.)

## 0.3.4 (2026-11-12)

- Settings in the web interface (admin, audited, in effect at once, stored in the database and laid over
  the configuration file): GeoIP account and license key, the local LLM server, the scheduled event
  analysis, focus sites, known scanners, catch-all hosts, paths changed by known automation, login notice,
  compliance level, password and lockout policy. Secrets are write-only (only "set, ends with …" is shown)
  and never written to the audit trail. config.toml keeps only what the program needs to start.
- Scheduled event analysis with a local, OpenAI-compatible LLM (new page "Analysis", its own sandboxed unit
  with an hourly timer and "Run now"): recent external events that no confident rule blocked are grouped by
  path, the model judges which are attack probes, and every answer is validated by the program (ids,
  regex compiles, is narrow, matches every observed form, matches no common or legitimate path) before it
  becomes an ordinary confident-block proposal. The analysis never approves anything; its proposals always
  wait for a person, also when automatic apply of tightening changes is on. Any LLM error: nothing proposed.
- "Test connection" for the LLM server runs in the analysis unit (the web service keeps no network access
  beyond localhost).
- Several rule operations as one change ("bundle"): checked, approved and applied together - one version,
  one nginx reload, one rollback. Uploading a rules file can propose all differences as one change; new
  rules keep their place in the file.
- Confident blocks can also cover internal sources ("external and internal, known scanners excepted");
  such a rule is never applied automatically and its sandbox test expects the internal request refused.
- A new raw rule can be placed right before a given managed rule (e.g. before 10299).
- Configuration changes by known automation (e.g. the CRS update, country lists) are recorded as
  "automation" instead of "outside" when their paths are listed.
- GeoIP: switching it on or off in Settings takes effect without a restart.
- Charts: a distribution bar is one framed track; stacked horizontal bars no longer look like two pieces.
- Consecutive button rows no longer touch.
- From an independent review: rule ids of a bundle are reserved like any other; at most 20 confident blocks
  per bundle and one pass over the access logs for all of them; every confident block of a bundle needs its
  own matching 403 test; a change whose rules would differ at apply time from the checked ones (e.g. known
  scanners changed meanwhile) is checked and approved again; the analysis refuses a model regex that could
  backtrack catastrophically before it meets any request data; known scanners must be internal and no wider
  than /16; a new LLM server address needs the API key entered again; rule comments never end in a
  backslash; many rules inserted before one rule keep their order; the sandbox's internal test address is
  never a known scanner.

## 0.3.3 (2026-11-12)

- Adoption: the root apply program also validates rule by rule (it re-checks every request itself and
  refused the 37 KB site file as a whole); a failure names the rule. Verified end to end with the first
  site's real rule files: both checks pass and the 51 managed rules are identical to the originals.
- An adoption that failed its checks can be checked again (admin).
- "This change loosens the WAF" is shown only for loosening changes, not for neutral ones such as adoption.
- The changes page opens with the list; the workflow explanation is one click away.
- Hourly chart: the total and the time are shown right at the pointer.
- Rule charts (overview, IP lookup, rules) show what a rule is: "930120 · local file access", with the rule's message.
- `doctor` / system check from the command line judge the collector by the service's recorded progress
  (no more false warning).

## 0.3.2 (2026-11-12)

- Adoption of real-sized rule files: the static check now runs rule by rule (the per-rule length limit was
  applied to the whole 37 KB file and refused the adoption); a failure names the rule.
- `@pmFromFile` / `@ipMatchFromFile` are accepted for `.data` lists inside the ModSecurity configuration
  directories (e.g. the CRS's own scanner list); any other file, a path with `..` or a URL is refused.
- Overview: coloured stat tiles with an hourly trend and the change against the previous window; active
  filters are unmistakable (highlighted bar, filled chips, a banner over the numbers); the hourly chart uses
  the full width and its crosshair follows the pointer exactly.
- Tables wider than the screen get a floating horizontal scrollbar at the bottom of the window.
- Livelier light theme: tinted page, card headers with an accent bar, tinted guides and tiles, zebra rows; the
  architecture diagram, the role cards and the WAF decision summary are coloured by meaning.
- Spacing: a notice no longer touches the page title buttons; checkboxes sit next to their explanation; flow
  step labels no longer wrap.
- GeoIP setup text says to add the [geoip] section.

## 0.3.1 (2026-11-12)

Install and upgrade
- `upgrade.sh`: checks first (installed version, no apply in progress, disk space, the release verified by the
  installed code with the pinned key, the configuration accepted by the new code), then a backup (program,
  units, configuration, database), then the switch with an explicit database migration and checks after the
  start (the service answers with the new version, program integrity, audit chain). Any failure after the
  service was stopped rolls back automatically and starts the previous version again. `--check` runs the checks
  only; `--rollback` puts back what an upgrade saved.
- New commands: `jt-waf-mgr config-check`, `migrate`, `doctor`.
- The audit trail records every change of the program version (a downgrade at priority crit).
- `tools/test_upgrade.sh`: release gate that installs the previous release in a staging root with data,
  upgrades, rolls back on an injected failure, rolls back by hand and upgrades again.

## 0.3.0 (2026-11-12)

Interface
- Every button has an icon; the site's own dropdowns and date picker replace the browser's; every list table
  can be sorted, filtered, paged and its columns chosen; light / dark / system theme; slightly larger text.
- Charts wherever there are numbers; guidance flow diagrams on the pages that are part of a process; a new
  Guide page with an interactive architecture diagram, first steps, the change workflow and the roles.
- A logo, used for the favicon, the top bar and the login page.
- The overview can be filtered (origin, outcome, site, source, rule…) by clicking values; it names the focus
  sites section.
- GeoIP: country, city and network owner (ASN) next to every external address, by-country and by-ASN charts.
- Rules files can be downloaded (current, any version, or the site's original before adoption) and uploaded:
  an upload is compared rule by rule and turned into ordinary proposals, each checked, sandboxed and approved.
- WAF decision diagram (/waf), generated from the configuration: which mechanisms block, which only score or
  log, which loosen, for external and internal sources, with the anomaly-score scale and every rule involved.
  The CRS page states the effective behaviour next to the global engine mode.
- Tablet and phone layouts: the top bar folds into a menu when the links do not fit.
- System check lists where the program, configuration, data and records are.

Security
- The root apply program no longer follows links in the service user's spool, keeps its lock and snapshots in
  its own root-only directory and restores from memory (a compromised service could otherwise have reached
  root or written unchecked directives into nginx).
- An apply is refused when a managed file was edited outside jt-waf-mgr, instead of silently overwriting the
  edit; an approver can explicitly restore the files. A failed apply keeps its version number in the history.
- Login: at most four scrypt checks at once, atomic failure counting, IPv6 limits per /64, wrong current
  passwords on "change password" count toward the lockout; invalid Content-Length is refused.
- The creator of an API token cannot approve changes proposed through it.
- systemd: the web service and the apply program may only talk to the loopback; the apply program can write only
  /etc/nginx, its state directory and the spool.
- Syslog audit lines carry `"severity": "crit"` for integrity alerts (files drop the syslog priority).
- Draft Wazuh rules for the audit lines (deploy/wazuh).
- Collector: redaction runs in linear time on clipped input (one long parameter used to stall the collector for
  seconds to hours); oversized records are kept as truncated events instead of being dropped; long transaction
  ids no longer collide; every cookie and the Authorization / Cookie headers are always masked; copytruncate
  rotation no longer loses lines; one bad record no longer blocks the rest.
- Evidence checks use ModSecurity's own decoding (`+`, %u, path normalisation) and no longer skip DAV paths,
  so a block that would hit real traffic cannot pass (or be auto-applied); regression samples need several
  distinct sources and skip catch-all hosts and paths with WAF events.
- Integrity: the append-only triggers are compared word for word; a purge beyond the retention period (or any
  purge when keeping forever) is reported; the whole program directory is checked (a module shadowing the
  standard library, bytecode caches and links are found); upgrades are verified with the installed code.
- GeoIP reader: bounded decoding work per lookup and type checks on every value.

## 0.2.1 (2026-11-12)

- The interface uses a plain "/" instead of the full-width slash in Chinese and Japanese texts; the
  i18n check now rejects the full-width slash.
- The incremental and the daily full audit-chain checks no longer write two identical anchors when they
  fall due together.
- The installer and the compliance guide explain how to set the append-only flag on the anchor file
  from the host when jt-waf-mgr runs in a container (LXC).

## 0.2.0 (2026-11-11)

The change workflow.

- Adoption: the existing site rule files become jt-waf-mgr managed files, rule for rule (verified by a
  decision-equivalence sandbox run: the same requests give the same results before and after).
- Templates: exclusion (narrowest scope; remove a target, a rule, a tag; score only; body parser),
  confident block (external sources only, decided by CRS's 949110), redaction (not inspected, never
  logged), plugin toggle, and expert raw rules (admin only, forbidden-directive list).
- Static checks (regex sanity, too broad, ReDoS shape and runtime test, id ranges, never reused ids).
- Evidence: access-log scan for confident blocks (external 2xx/3xx, internal hits), alert impact for
  exclusions; an override needs a written justification and is never auto-applied.
- Sandbox: a throwaway nginx with the production configuration plus the change; user test cases,
  encoding / case / slash variants, internal-source check, per-site regression samples.
- Approval: proposer cannot approve (single-admin mode with OTP for one's own loosening); loosening
  always needs a person; optional auto-apply for qualifying tightening with a daily limit.
- Root apply program (systemd path unit): validates again, snapshot, nginx -t, reload, verifies new
  workers, waits for old ones, health check before/after, automatic restore on any failure;
  manual-edit detection; versions and one-click rollback.

Integrity and compliance:

- Audit trail hash chain (sha256 of the previous hash and the canonical row), append-only table
  (triggers), retention purge that keeps the chain verifiable; anchors every 5 minutes in an
  append-only file (chattr +a) and in syslog; every syslog line carries the row's id and hash;
  verification incremental / daily / on demand; NDJSON export with hashes, verifiable offline.
- Signed releases: release/MANIFEST.sha256 (every file) signed with the release key (RSA-3072); the
  installer verifies before installing and pins the key; the service (hourly) and the root apply
  program (every run, refusing on failure) check the installed files, units and wrapper;
  `jt-waf-mgr verify-release` before upgrades; CycloneDX SBOM.
- Configuration fingerprints (nginx / ModSecurity / CRS files, nginx binary, module) every 5 minutes;
  each change recorded and attributed (jt-waf-mgr or outside).
- Accounts: password character classes, history, optional maximum / minimum age; account expiry;
  dormant accounts disabled; session limit; own sessions list; sign out everywhere; previous sign-in
  and failed attempts shown after sign-in; login notice; account review export; lockouts audited
  as critical.
- Daily database backup with integrity check and SHA-256, verification on demand.
- System check page (program integrity, audit chain, anchors, syslog, time sync, disk, database,
  backups, collector, apply program, configuration changes, accounts, web settings) and Compliance
  page (ISO/IEC 27001:2022, Taiwan Cyber Security Management Act baseline, OWASP Top 10:2025),
  computed from the live configuration. docs/COMPLIANCE.md, SECURITY.md.
- Every write API route audits (enforced by a test); denied approvals and rollbacks are audited; the
  OTP for approving one's own loosening is replay-protected.

## 0.1.0 (unreleased)

First version: read-only.

- ModSecurity v3 JSON audit log collector with rotation handling and sensitive-field masking.
- Overview, events, event detail, rules, sites, CRS status, IP lookup.
- Local accounts with TOTP, roles, API tokens with scopes, audit trail to database and syslog.
- Read-only API: status, overview, events (filters, stats, NDJSON export with cursor and SHA-256),
  rules, removals, sites, CRS, IP lookup.
- UI in English, Traditional Chinese (Taiwan) and Japanese.
- Offline installer with a hardened systemd unit; no third-party Python packages.
