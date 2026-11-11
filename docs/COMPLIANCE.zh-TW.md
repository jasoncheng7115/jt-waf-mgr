# 合規對照

本文件說明 jt-waf-mgr 在哪些地方支援常見的資安控制措施，以及使用單位仍需自行處理的部分。
這裡只列程式實際做到的事。介面上的「合規檢核」頁（admin）會依目前的設定，即時算出每一項的狀態；本文件說明這些對照的依據。

參照的規範：
- **ISO/IEC 27001:2022** 附錄 A
- **資通安全管理法**：《資通安全責任等級分級辦法》附表十「資通系統防護基準」。構面與措施名稱沿用附表十。
  - 各項要求依系統的防護需求等級（普/中/高）而不同。
  - 評估時請以主管機關公告的最新版本為準。
- **OWASP Top 10:2025**

防護需求等級設定在 `/etc/jt-waf-mgr/config.toml`：

```toml
[compliance]
level = "medium"     # ""、"low"（普）、"medium"（中）、"high"（高）
```

這個設定不改變任何行為，只決定「合規檢核」頁拿哪個等級的要求比對目前設定，並列出不足的項目。

## 存取控制

### 帳號管理（account_management）
ISO A.5.16、A.5.18 · 資安法 存取控制－帳號管理 · OWASP A01
- 本機帳號有四種角色。
- 帳號可以設定到期日（`expires_at`），到期後自動停用。
- 超過 `auth.dormant_days`（預設 90）天沒有登入的帳號會自動停用；最後一個啟用中的 admin 不會被停用。
- 帳號審查：「使用者 → 帳號審查」（`GET /api/v1/users/review`）列出：
  - 所有帳號：角色、狀態、最後登入時間與來源、閒置天數；
  - 所有有效的 API token。
- 每次審查都寫一筆稽核記錄。審查結果可下載 CSV/JSON 留存。
- 帳號的每個異動都有稽核記錄：建立、角色、停用/啟用、重設、解鎖、到期日、強制登出。

### 最小權限（least_privilege）
ISO A.5.15、A.8.2、A.8.3 · 資安法 存取控制－最小權限 · OWASP A01
- 角色權限：
  - viewer：唯讀；
  - operator：提出變更；
  - approver：核准與還原；
  - admin：收編規則檔，管理帳號、token 與設定。
- API token 有權限範圍（scope）與來源網段限制，永遠不能核准變更、管理 token 或改設定。

### 職責分離（segregation_of_duties）
ISO A.5.3、A.8.32 · OWASP A06
- 變更的提出者不能核准自己的變更。
- 放寬類變更一定要由人核准；token 只能提出。
- 單人模式（只有一位管理者的站台）是明確的設定，開關都有稽核記錄。在單人模式下，核准自己提出的放寬變更，要重新輸入 OTP 並填寫理由。

### 連線逾時（session_timeout）
ISO A.8.5 · 資安法 存取控制－帳號管理（逾越閒置時間自動登出） · OWASP A07
- 兩種逾時：
  - 閒置逾時：`server.session_idle_minutes`，預設 30 分鐘；
  - 絕對逾時：`server.session_max_hours`，預設 12 小時。
- 每位使用者的同時連線數有上限（`auth.max_sessions_per_user`）。
- 使用者可以查看並結束自己的其他連線；admin 可以強制某位使用者全部登出。

## 識別與鑑別

### 身分驗證管理（authentication）
ISO A.5.17、A.8.5 · 資安法 識別與鑑別－身分驗證管理 · OWASP A07
- 密碼以 scrypt 雜湊儲存。暫時密碼在第一次登入時必須變更。
- 密碼原則（都在 `[auth]` 設定）：
  - 最短長度：12；
  - 字元類別：4 類中至少 3 類；
  - 不可與前 N 次密碼相同：3；
  - 最長效期（到期後登入時強制變更）與最短效期，可選用。
- 連續失敗 `lockout_threshold` 次後鎖定 `lockout_minutes` 分鐘（5 次/15 分鐘）。
  - 鎖定會寫稽核記錄，syslog 等級為 crit。
  - 另有每個來源位址的嘗試次數限制。
- 中、高等級系統：請設定 `password_max_age_days` 與 `password_min_age_hours`。

### 內部使用者之識別與鑑別（multi_factor）
ISO A.8.5 · 資安法 識別與鑑別－內部使用者之識別與鑑別 · OWASP A07
- TOTP（RFC 6238），有防重放保護。
- 預設 approver 與 admin 必須啟用（`auth.require_totp_roles`）。
- 高等級系統：請要求所有角色都啟用。

### 鑑別資訊回饋（auth_feedback）
ISO A.8.5 · 資安法 識別與鑑別－鑑別資訊回饋 · OWASP A07
- 密碼與 OTP 的輸入一律遮蔽。
- 帳號不存在與密碼錯誤，回應內容與時間都相同。
- 登入後會顯示上次登入的時間與來源，以及之後失敗嘗試的次數。

## 事件日誌與可歸責性

### 記錄事件、日誌紀錄內容（audit_logging）
ISO A.8.15 · 資安法 記錄事件、日誌紀錄內容 · OWASP A09
- 每個操作都寫一筆稽核記錄，內容包含：時間、操作者、操作者類型（使用者/token/系統）、來源位址、動作、結果、細節。
- 涵蓋的操作：
  - 登入、登出、失敗與鎖定；
  - 帳號、token、設定的異動；
  - 每個變更的提出、檢查、核准、退回、套用、還原；
  - 匯出、審查、備份、完整性檢查結果。
- 同一筆記錄也以一行 JSON 送到 syslog（程式名稱 `jt-waf-mgr:`），附上該筆的 id 與雜湊值。
- 有一個測試會逐一檢查 API 的每個寫入路徑，沒有寫稽核記錄就會失敗。

### 日誌資訊之保護（log_protection）
ISO A.8.15、A.5.33 · 資安法 日誌資訊之保護 · OWASP A09
- **雜湊鏈**：每筆記錄存 `sha256(前一筆雜湊＋本筆內容)`。竄改、插入或刪除任何一筆，鏈就會斷。
- **只能新增**：稽核資料表由資料庫觸發器禁止修改與刪除。
  - 保存期限（`retention.audit_days`）預設 0，也就是永久保存。
  - 設定保存期限時，只會刪除最舊的一段，剩下的鏈仍可驗證。
- **錨點**：每 5 分鐘把最新一筆的（id、雜湊）追加到 `/var/lib/jt-waf-mgr/audit-anchors.jsonl`，並送到 syslog。
  - 這個檔案設為 append-only（`chattr +a`），服務帳號只能追加，不能修改或刪除。
  - 在 LXC 等容器裡，容器內沒有設定這個旗標的權限（CAP_LINUX_IMMUTABLE），安裝程式會發出警告。請從主機端設定，例如 Proxmox：
    `chattr +a /proc/$(lxc-info -n <CTID> -p -H)/root/var/lib/jt-waf-mgr/audit-anchors.jsonl`。
    這個旗標在容器重開後仍保留（存在檔案系統上）。做不到時，送到 SIEM 的 syslog 錨點就是唯一的獨立副本。
  - 即使有人改了資料庫並重算整條鏈，也會和錨點對不上。
- 驗證時機：
  - 每 5 分鐘（增量）；
  - 每天（完整）；
  - 隨時手動執行（稽核記錄頁的「驗證完整性」按鈕）；
  - 命令列 `jt-waf-mgr integrity`。
- 驗證失敗時寫一筆 `integrity.audit_chain_failed` 稽核記錄，syslog 等級為 crit。

### 日誌處理失效之回應（log_failure_response）
ISO A.8.16 · 資安法 日誌處理失效之回應 · OWASP A09
- syslog 送出失敗會計數，並顯示在「系統檢查」頁。
- 以下情況都以 crit 等級記錄，供 SIEM 告警：完整性檢查失敗、備份失敗、帳號鎖定。問題未解除前每 12 小時重複一次。

### 日誌儲存容量（log_capacity）
ISO A.8.6 · 資安法 日誌儲存容量
- 會檢查資料庫所在位置的剩餘空間（`integrity.disk_min_free_mb`）。
- 各類資料的保存期限都可以設定：
  - 事件：`retention.events_days`，30 天；
  - 統計：`retention.stats_days`，365 天；
  - 稽核：`retention.audit_days`，0＝永久。

### 時戳及校時（time_sync）
ISO A.8.17 · 資安法 時戳及校時
- 「系統檢查」頁會顯示主機時鐘是否已與 NTP 同步。
  - 資料來源是 systemd-timedated，systemd-timesyncd 與 chrony 都適用。
- 所有記錄的時間都帶時區。

### 資通系統監控/SIEM 轉送（siem_forwarding）
ISO A.8.16 · 資安法 資通系統監控
- syslog（預設 facility `local0`）會帶出每一筆稽核記錄與錨點。
- 轉送到 SIEM 要在 rsyslog/journald 設定，屬於使用單位的管理措施。

### 證據匯出（evidence_export）
ISO A.5.28
- `GET /api/v1/audit/export`（admin）匯出 NDJSON：
  - 每一筆都附雜湊值；
  - 最後一行是摘要，含全部內容的 SHA-256。
- 用 `jt-waf-mgr audit-verify 檔案` 可以離線驗證。
- 事件匯出（`/events/export`）也附 SHA-256。

## 系統與資訊完整性、組態與變更

### 軟體及資訊完整性（software_integrity）
ISO A.8.19、A.8.32 · 資安法 軟體及資訊完整性 · OWASP A08、A03
- **發行檔**：附 `release/MANIFEST.sha256`（每個檔案的 SHA-256），並以發行金鑰（RSA-3072）簽章。
- **安裝時**：安裝程式先驗證每個檔案與簽章才會安裝，第一次安裝時固定（pin）金鑰。
- **執行時**：服務每小時檢查一次，root 套用程式每次執行前也會檢查。
  - 檢查範圍：已安裝的檔案（程式、systemd unit、指令包裝檔）是否與簽章清單一致。
  - 程式目錄裡多出不在清單上的檔案，也算失敗。
  - 檢查失敗時，套用程式拒絕執行。
- **升級前**：先用已安裝的程式驗證新版本：`jt-waf-mgr verify-release <解開的目錄>`。
- 每個發行檔都附 SBOM：`sbom.cdx.json`（CycloneDX 1.5）。

### 組態管理（configuration_management）
ISO A.8.9 · OWASP A02
- 每 5 分鐘計算一次指紋（SHA-256），範圍包括：
  - 所有 nginx/ModSecurity/CRS 設定檔；
  - nginx 執行檔；
  - ModSecurity 模組。
- 每次變動都會記下新增、刪除、修改的檔案，並判斷來源：
  - jt-waf-mgr：套用的版本造成；
  - 外部：其他來源，例如手動修改、套件升級。
- 外部變動會寫稽核記錄（`config.changed`，結果 `outside`），並列在「設定異動」頁。
- 受管理的規則檔帶 SHA-256 標頭。檔案被手動修改時會被偵測到，套用程式拒絕覆蓋。

### 變更管理（change_management）
ISO A.8.32、A.8.31 · 資安法 系統發展生命週期 · OWASP A06
- 每個規則變更都依序經過：
  1. 靜態檢查：正規式合理性、ReDoS、ID 範圍、禁用指令；
  2. 存取記錄佐證；
  3. 沙箱測試：臨時 nginx，使用正式設定加上這次變更，跑測試案例與回歸樣本；
  4. 核准；
  5. 由 root 程式套用：`nginx -t`、reload、確認生效、健康檢查，任何一步失敗都自動還原。
- 每個版本都保留，可以一鍵還原。

### 系統備份（backup）
ISO A.8.13 · 資安法 營運持續計畫－系統備份
- 每天備份資料庫：
  - 使用 SQLite 線上備份；
  - 對備份檔執行 `integrity_check`；
  - 另存一份 SHA-256 檔；
  - 檔案權限 0600。
- 備份保留 `backup.keep_days`（14）天。
- 隨時可以手動備份與驗證：介面、`jt-waf-mgr backup`、`jt-waf-mgr backup --verify 檔名`。
- 每個版本的受管理 nginx 檔案，由套用程式另外保存在 `spool/backups`。
- 把備份複製到其他主機，屬於使用單位的管理措施。

## 資料保護

### 敏感資料遮蔽（data_masking）
ISO A.8.11、A.8.12 · 資安法 資料儲存之安全
- 敏感欄位（`waf.sensitive_fields`：password、token、otp、secret…）的值，在寫入資料庫之前就遮蔽。
- 遮蔽範圍包括參數、比對到的資料、網址。
- 沒有任何 API 能看到原文。

### 資料儲存之安全（data_at_rest）
ISO A.8.24 · 資安法 資料儲存之安全
- 資料庫檔案權限 0600，所在目錄 0700，屬於服務帳號。
- jt-waf-mgr 本身不加密資料庫，因為 Python 標準函式庫沒有 AES；資料庫裡也不含敏感欄位原文（見上一節）。
- 高等級系統：請使用磁碟加密（使用單位的管理措施）。

### 傳輸之機密性與完整性（transport）
ISO A.8.24、A.8.20 · 資安法 傳輸之機密性與完整性
- 服務只聽 loopback。
- 管理網站由 nginx 處理 TLS（1.2/1.3、HSTS），範例見 `deploy/nginx-vhost.conf.example`。
- cookie 設為 `Secure`，並使用 `__Host-` 前綴。

### 資料保存期限（retention）
ISO A.8.10
- 事件、統計、稽核記錄超過設定的保存期限後清除。
- 備份超過 `backup.keep_days` 後刪除。

## 開發與維運

### 安全開發（secure_development）
ISO A.8.25、A.8.26、A.8.28、A.8.29 · 資安法 系統發展生命週期 · OWASP A03、A05、A10
- 不使用任何第三方 Python 套件。
- 前端：CSP 不允許 `unsafe-inline`，不使用 `v-html`。
- 後端：SQL 一律參數化，不使用 `shell=True`。
- 有單元測試與 API 測試，包含權限與稽核覆蓋率。
- 發行前的 preflight 會掃描內部資料與機密。

### 漏洞修復（vulnerability_management）
ISO A.8.8 · 資安法 漏洞修復
- 介面上顯示 nginx、CRS、ModSecurity 的版本。
- 作業系統、nginx、CRS 的更新屬於使用單位的管理措施。
- jt-waf-mgr 本身的弱點，請依 [SECURITY.md](../SECURITY.md) 回報。

### 資通系統監控（monitoring）
ISO A.8.16、A.8.20 · 資安法 資通系統監控
- jt-waf-mgr 收集並呈現 WAF 自身的事件。

## 使用單位需要自行處理的事

- 把 syslog 轉送到獨立的 SIEM，並使用不可改寫的儲存。對以下事件設定告警：
  - `integrity.*`；
  - `backup.failed`；
  - `account.locked`；
  - `config.changed`（結果 `outside`）。
- 定期做帳號審查（使用者 → 帳號審查），並保存下載的審查記錄。
- 把每天的資料庫備份複製到其他主機，每年至少做一次還原測試。
- 管理網站只開放給管理網段。
- 更新作業系統、nginx、libmodsecurity、CRS。
- 讓主機時鐘保持 NTP 同步。
- 發行私鑰不要放在正式機上；正式機只裝公鑰。

## 驗證方式

```sh
jt-waf-mgr integrity                         # 程式檔案（簽章清單）＋稽核雜湊鏈＋錨點
jt-waf-mgr verify-release ./jt-waf-mgr-X.Y.Z    # 用已固定的金鑰驗證解開的新版本
jt-waf-mgr audit-verify export.ndjson        # 離線驗證稽核匯出檔
jt-waf-mgr backup --verify jt-waf-mgr-YYYYMMDD-HHMMSS.db
cd /usr/lib/jt-waf-mgr && sha256sum -c --ignore-missing release/MANIFEST.sha256
openssl dgst -sha256 -verify /etc/jt-waf-mgr/release-key.pem \
    -signature /usr/lib/jt-waf-mgr/release/MANIFEST.sha256.sig /usr/lib/jt-waf-mgr/release/MANIFEST.sha256
lsattr /var/lib/jt-waf-mgr/audit-anchors.jsonl    # 應該看到 a（append-only）旗標
```

資料存放位置：
- 資料庫：`/var/lib/jt-waf-mgr/jt-waf-mgr.db`。內容包括：
  - 事件（已遮蔽）、統計；
  - 稽核記錄、帳號；
  - 變更、版本、設定指紋。
- 錨點：`/var/lib/jt-waf-mgr/audit-anchors.jsonl`。
- 備份：`/var/lib/jt-waf-mgr/backups/`。
- 受管理的 nginx 檔案：`/etc/nginx/modsec/jt-waf-mgr/`，各版本的舊檔在 `/var/lib/jt-waf-mgr/spool/backups/`。
- 設定檔：`/etc/jt-waf-mgr/config.toml`。
- 固定的發行公鑰：`/etc/jt-waf-mgr/release-key.pem`。
