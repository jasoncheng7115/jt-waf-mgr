# 安全政策

[English](SECURITY.md) · **繁體中文** · [日本語](SECURITY_ja.md)

## 回報弱點

請使用本倉庫的 GitHub **私下弱點回報**功能（Security → Report a
vulnerability）。請不要開公開的 issue。

- 確認收到：3 個工作天內。
- 經確認的高風險或嚴重問題，修正或緩解措施：目標 7 天內。其他問題隨下一個版本發佈。
- 除非您要求不具名，否則會在 changelog 中致謝。

只支援最新的版本。

## 設計摘要

以下是程式實際做到的事；[合規對照](docs/COMPLIANCE.md)把每一項連結到它所支援的
控制措施。

### 程序與權限分離

- 網頁服務以無特權的 `jtwaf` 使用者執行，只聽 loopback。
- systemd unit 已強化：`ProtectSystem=strict`、空的 capability 集合、系統呼叫過濾，以及不可取得新權限（no new privileges）。
- 只有套用程式以 root 執行。它由 systemd path unit 啟動，絕不由服務啟動，並且：
  - 重新驗證每個請求：允許的指令清單、檢查碼、規則 id 範圍，以及手動修改偵測；
  - 只寫入受管理的檔案；
  - 每個變更都經過測試、reload、確認生效與健康檢查，任何一步失敗都還原先前的檔案；
  - 絕不執行取自請求的任何內容（任何地方都沒有 `shell=True`）；
  - 已安裝的程式與簽章清單不一致時拒絕執行；
  - 把 spool 視為不可信任（它屬於服務帳號）：目錄只開啟一次且不跟隨連結，請求以 `O_NOFOLLOW`
    開啟並在開啟後檢查，結果以獨占建立的方式寫入再原地改名，因此預先放好的連結無法讓 root 寫到別處；
  - 鎖與快照放在自己專用、只有 root 能存取的目錄（`/var/lib/jt-waf-mgr-apply`），還原時使用
    已讀進記憶體的內容，絕不使用可能被調包的檔案；
  - 受管理的檔案在 jt-waf-mgr 之外被修改時（drift）拒絕套用，而不是覆蓋那份修改；approver
    可以明確地還原目前的版本，這個動作以 crit 等級記錄；
  - 在 systemd 的限制下執行：只能寫入 `/etc/nginx`、自己的狀態目錄與 spool，沒有任何裝置，
    而且只能連 loopback（健康檢查用）。
- 網頁服務只能連 loopback（`IPAddressDeny=any`、`IPAddressAllow=localhost`）：即使服務
  被攻破，也無法對外連線。GeoIP 下載在自己的短暫 unit 中執行。

### 供應鏈

- 後端只使用 Python 標準函式庫，完全沒有任何第三方 Python 套件。
- 介面套件包含 Vue 與 Vue Router，版本列在發行檔的 SBOM（`sbom.cdx.json`，CycloneDX 1.5）。
- 每個發行檔都附 `release/MANIFEST.sha256`，內含每個檔案的 SHA-256，並以專案的發行金鑰（RSA-3072、SHA-256）簽章。
- 安裝程式在安裝任何東西之前，會先檢查每個檔案與簽章。升級時，用已安裝（且本身已驗證過）的
  程式碼檢查；第一次安裝時只能用發行檔裡附的程式碼，因此請先驗證 tarball：
  `openssl dgst -sha256 -verify release-key.pem -signature …`（見下方），升級時也可以用
  `jt-waf-mgr verify-release <unpacked dir>`。
  - 第一次安裝時把金鑰固定（pin）在 `/etc/jt-waf-mgr/release-key.pem`。
  - 之後的版本必須以已固定的金鑰簽章；換新金鑰需要 `--accept-new-key`。
- 升級前，`jt-waf-mgr verify-release <unpacked dir>` 會用已安裝、已驗證的程式碼檢查新版本。
- 執行時，服務每小時檢查一次（套用程式每次執行前也會檢查）已安裝的檔案是否與簽章清單一致：
  - 沒有被修改、沒有缺少、/usr/lib/jt-waf-mgr 底下任何地方都沒有多出檔案（放在那裡的模組會
    蓋過標準函式庫）、沒有 bytecode 快取、沒有符號連結；
  - systemd unit 與指令包裝檔也一併檢查。
- tarball 本身也附 `.sha256` 與分離式簽章：

  ```sh
  openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-X.Y.Z.tar.gz.sig jt-waf-mgr-X.Y.Z.tar.gz
  ```

### 網頁

- Content-Security-Policy 不允許 `unsafe-inline`，也沒有任何第三方來源。
- 其他回應標頭：`X-Frame-Options: DENY`、`nosniff`、`Referrer-Policy: no-referrer`、COOP / CORP 與 Permissions-Policy。
- 連線 cookie 使用 `__Host-` 前綴，並設為 `Secure`、`HttpOnly` 與 `SameSite=Lax`。只儲存連線 id 的 SHA-256。
- 每個寫入都需要 CSRF 標頭並檢查 Origin。
- 攻擊者控制的內容（網址、user agent、比對到的資料、規則內容）一律以文字顯示：不使用 `v-html`，也不使用 `innerHTML`。
- 敏感的請求值（密碼、權杖、OTP…）在儲存任何東西之前就遮蔽。沒有任何 API 能顯示原文。

### 帳號

- 密碼以 scrypt 雜湊（N=2^15、r=8、p=1）。
- 密碼原則：最短長度與字元類別、歷史記錄，以及可選用的最長與最短效期。
- approver 與 admin 必須使用 TOTP（RFC 6238，有防重放保護）。
- 多次失敗後鎖定，以原子方式計數（同時進行的猜測每一次都會計入），另有每個來源位址的次數限制
  （IPv6 以 /64 計）。帳號不存在時，回應的錯誤與時間都和密碼錯誤相同。
- 同時最多執行四個密碼檢查（scrypt，每個 32 MiB），因此大量登入不會耗盡服務的
  記憶體；其餘的會被告知稍後重試。
- 「變更密碼」時輸入錯誤的目前密碼，和登入失敗一樣計入鎖定次數。
- 透過 API 權杖提出的變更，屬於建立該權杖的人：他不能核准這個變更。
- 帳號可以設定到期，閒置過久會停用。每位使用者有連線數上限，可以查看自己的連線清單，admin 也可以「強制全部登出」。
- API 權杖：
  - 只儲存它的 SHA-256；
  - 有權限範圍與來源網段限制，可選用到期日；
  - 永遠不能核准變更、管理帳號或權杖，也不能改設定。

### 稽核記錄

- 每個操作都會寫入稽核資料表，並以一行 JSON 送到 syslog。
- 每一筆都存 `sha256(previous hash + canonical row)`。SQLite 觸發器讓資料表只能新增；保存期限清除只會刪除最前面的一段，並保持雜湊鏈可驗證。
- 觸發器本身也會逐字檢查（名稱正確但內容是空的觸發器不會通過）。
  記錄只能透過保存期限清除而消失，而且只限超過保存期限的記錄：
  在預設值（永久保存）下，任何清除都會被回報。
- 每隔幾分鐘，最新一筆的（id、雜湊）會追加到一個 append-only 檔案（`chattr +a`）並送到 syslog。被改寫或截斷的雜湊鏈，將與這些錨點對不上，也與 SIEM 隨每一筆收到的雜湊值對不上。
- 稽核匯出為 NDJSON，附雜湊值以及所有行的 SHA-256，可以用 `jt-waf-mgr audit-verify` 離線驗證。

### 這些保護的限制

- 在容器（LXC）裡，append-only 旗標必須從主機端設定；容器本身無法設定。
- 主機上的 root 可以改任何東西。錨點與 syslog 副本讓竄改可以被偵測，但無法讓竄改變得不可能。
  - 請把 syslog 轉送到獨立的 SIEM，並使用不可改寫的儲存。
  - 請留意 `integrity.*` 稽核動作；它們以 syslog 等級 `crit` 記錄。
- 資料庫在儲存時沒有加密；標準函式庫沒有 AES。它以檔案權限保護（0600，目錄 0700）。
  - 敏感的請求值從不寫入資料庫。
  - 若貴單位的政策要求，請使用磁碟加密。
- 管理用的 vhost 必須維持只限內部網路存取（見 `deploy/nginx-vhost.conf.example`）。

## 已接受的風險

- 密碼正確之後，伺服器才會要求輸入 TOTP 驗證碼，這會讓客戶端知道密碼是
  正確的。這是常見的兩段式登入；鎖定、次數限制與稽核記錄（搭配 SIEM
  對登入失敗與鎖定的告警）限制了攻擊者能得知的資訊。

- 服務會執行沙箱（127.0.0.1 上的臨時 nginx），因此它的 unit 不能使用 `MemoryDenyWriteExecute`：PCRE JIT 需要這個能力，正式環境的 nginx 也一樣。
