# Offline hosts: installing and upgrading

**English** · [繁體中文](OFFLINE.zh-TW.md) · [日本語](OFFLINE.ja.md)

jt-waf-mgr uses only the Python standard library: no pip, no Docker, and it makes no outside connection to install or
run. On a host without internet access, bring the files in from a computer that has it. Below, "online computer" is a
computer with internet access and "host" is the server you install on.

## 1. Prepare the files on an online computer

From [GitHub Releases](https://github.com/jasoncheng7115/jt-waf-mgr/releases), download the four files of one version:

- `jt-waf-mgr-<version>.tar.gz`
- `jt-waf-mgr-<version>.tar.gz.sig`
- `jt-waf-mgr-<version>.tar.gz.sha256`
- `release-key.pem`

Verify them once there (the host verifies again):

```sh
sha256sum -c jt-waf-mgr-<version>.tar.gz.sha256
openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-<version>.tar.gz.sig jt-waf-mgr-<version>.tar.gz
openssl pkey -pubin -in release-key.pem -outform DER | sha256sum
```

The key fingerprint the last line prints must be:

```
ae3c8d2c761419d1482c21aa46ae09425f766737c6b5c8b181d8bd42f92049f9
```

## 2. System packages the host needs

- Python 3.11 or newer: Debian 12 / 13 and Ubuntu 24.04 have it.
- nginx, the ModSecurity-nginx connector and libmodsecurity 3.0.9 or newer: from an internal apt mirror; without one,
  download the .deb files on a system of **the same release** (a throwaway VM, for example) and bring them in:

  ```sh
  # online computer (same Debian / Ubuntu release as the host)
  sudo apt-get install --download-only nginx libnginx-mod-http-modsecurity
  cp /var/cache/apt/archives/*.deb ./debs/
  # host
  sudo dpkg -i ./debs/*.deb
  ```

- OWASP CRS 4: on the online computer, download the release and its `.asc` from
  [CRS's GitHub releases](https://github.com/coreruleset/coreruleset/releases), verify with `gpg --verify`, bring it in
  and install it as section 3 of the [ModSecurity installation guide](MODSECURITY.md) describes.

## 3. Install

Bring the four files of section 1 to the host (USB stick, internal file server...), then:

```sh
sha256sum -c jt-waf-mgr-<version>.tar.gz.sha256
openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-<version>.tar.gz.sig jt-waf-mgr-<version>.tar.gz
tar xzf jt-waf-mgr-<version>.tar.gz && cd jt-waf-mgr-<version>
sudo ./install.sh                   # checks every file and the release signature, and pins the key
sudo jt-waf-mgr check
sudo jt-waf-mgr user add <name> --role admin
```

## 4. Upgrade

Download the four files of the new version on the online computer, bring them in, then:

```sh
sha256sum -c jt-waf-mgr-<new>.tar.gz.sha256
tar xzf jt-waf-mgr-<new>.tar.gz && cd jt-waf-mgr-<new>
sudo ./upgrade.sh --check           # checks only: the new release, verified with the installed program and pinned key
sudo ./upgrade.sh                   # backup, switch, checks; rolls back by itself if any step fails
```

`upgrade.sh` uses the key pinned at installation, so a modified release or one signed by anyone else is refused.
To go back: `sudo ./upgrade.sh --rollback`.

## 5. Features that need the network, offline

- **GeoIP** (country, network owner, world map): on the online computer, download `GeoLite2-City.mmdb` and
  `GeoLite2-ASN.mmdb` with your MaxMind account and put them in `/var/lib/jt-waf-mgr/geoip/` on the host (owner
  `jtwaf`, mode 0640). Keep GeoIP switched on in Settings (the default); no key is needed; repeat to update.
- **Event analysis (LLM)**: an OpenAI-compatible LLM server on the internal network (llama.cpp, vLLM, Ollama...) needs
  no internet anyway.
- **Notifications**: e-mail through an internal SMTP server, Zulip or Nextcloud Talk on internal servers, a generic
  webhook to an internal system; Telegram, Teams, Slack and Discord need their outside services.
- **Log servers (syslog / SIEM)**: internal log servers.
- **CRS updates**: bring a new CRS release in as in section 2.
