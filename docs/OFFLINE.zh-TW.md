# 離線環境：安裝與更新

[English](OFFLINE.md) · **繁體中文** · [日本語](OFFLINE.ja.md)

jt-waf-mgr 本身只用 Python 標準函式庫，不需要 pip、不需要 Docker，也不會在安裝或執行時連外。沒有對外網路的主機，只要
把檔案從一台能上網的電腦帶進去即可。以下「外網電腦」指能上網的電腦，「主機」指要安裝的伺服器。

## 1. 在外網電腦準備檔案

從 [GitHub Releases](https://github.com/jasoncheng7115/jt-waf-mgr/releases) 下載同一版的四個檔案：

- `jt-waf-mgr-<版本>.tar.gz`
- `jt-waf-mgr-<版本>.tar.gz.sig`
- `jt-waf-mgr-<版本>.tar.gz.sha256`
- `release-key.pem`

先在外網電腦驗證一次（主機上還會再驗一次）：

```sh
sha256sum -c jt-waf-mgr-<版本>.tar.gz.sha256
openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-<版本>.tar.gz.sig jt-waf-mgr-<版本>.tar.gz
openssl pkey -pubin -in release-key.pem -outform DER | sha256sum
```

最後一行印出的公鑰指紋必須是：

```
ae3c8d2c761419d1482c21aa46ae09425f766737c6b5c8b181d8bd42f92049f9
```

## 2. 主機需要的系統套件

- Python 3.11 以上：Debian 12 / 13 與 Ubuntu 24.04 預設就有。
- nginx、ModSecurity-nginx 連接器、libmodsecurity 3.0.9 以上：從內部的 apt 鏡像安裝；沒有鏡像時，在**同版本**的系統
  （例如一台拋棄式 VM）下載 .deb 帶進去：

  ```sh
  # 外網電腦（與主機同一版 Debian / Ubuntu）
  sudo apt-get install --download-only nginx libnginx-mod-http-modsecurity
  cp /var/cache/apt/archives/*.deb ./debs/
  # 主機
  sudo dpkg -i ./debs/*.deb
  ```

- OWASP CRS 4：在外網電腦從 [CRS 的 GitHub releases](https://github.com/coreruleset/coreruleset/releases) 下載發行檔與
  `.asc`，以 `gpg --verify` 驗證後帶進主機，照 [ModSecurity 安裝手冊](MODSECURITY.zh-TW.md) 第 3 節安裝。

## 3. 安裝

把第 1 節的四個檔案帶到主機（USB、內部檔案伺服器等），然後：

```sh
sha256sum -c jt-waf-mgr-<版本>.tar.gz.sha256
openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-<版本>.tar.gz.sig jt-waf-mgr-<版本>.tar.gz
tar xzf jt-waf-mgr-<版本>.tar.gz && cd jt-waf-mgr-<版本>
sudo ./install.sh                   # 驗證每個檔案與發行檔簽章，並記住（pin）這把公鑰
sudo jt-waf-mgr check
sudo jt-waf-mgr user add <帳號> --role admin
```

## 4. 更新

同樣在外網電腦下載新版的四個檔案、帶進主機，然後：

```sh
sha256sum -c jt-waf-mgr-<新版>.tar.gz.sha256
tar xzf jt-waf-mgr-<新版>.tar.gz && cd jt-waf-mgr-<新版>
sudo ./upgrade.sh --check           # 只做檢查：用已安裝的程式與 pin 住的公鑰驗證新版
sudo ./upgrade.sh                   # 備份、切換、檢查；任何一步失敗自動還原
```

`upgrade.sh` 用的是安裝時 pin 住的公鑰，所以換過的發行檔或別人簽的檔案都會被拒絕。需要退回時：
`sudo ./upgrade.sh --rollback`。

## 5. 需要網路的功能在離線時怎麼辦

- **GeoIP**（國家、網路業者、世界地圖）：在外網電腦用你的 MaxMind 帳號下載 `GeoLite2-City.mmdb` 與
  `GeoLite2-ASN.mmdb`，放到主機的 `/var/lib/jt-waf-mgr/geoip/`（擁有者 `jtwaf`、權限 0640）。設定頁的 GeoIP 保持啟用（預設），不必填金鑰；
  要更新時重複這一步。
- **事件分析（LLM）**：用內部網路上的 OpenAI 相容 LLM 伺服器（llama.cpp、vLLM、Ollama…），本來就不需要外網。
- **通知**：Email 用內部 SMTP、Zulip 或 Nextcloud Talk 用內部伺服器、通用 webhook 指向內部系統都可以；Telegram、
  Teams、Slack、Discord 需要連到外部服務。
- **外送記錄（syslog / SIEM）**：送到內部的記錄伺服器即可。
- **CRS 更新**：照第 2 節的方式帶進新版 CRS。
