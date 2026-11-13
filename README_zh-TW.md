# jt-waf-mgr v0.4.18

[English](README.md) · **繁體中文** · [日本語](README_ja.md)

[![License](https://img.shields.io/github/license/jasoncheng7115/jt-waf-mgr?color=blue)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/jasoncheng7115/jt-waf-mgr)](https://github.com/jasoncheng7115/jt-waf-mgr/commits/main)
![Python](https://img.shields.io/badge/Python-3.11%2B%20stdlib%20only-3776AB?logo=python&logoColor=white)
![Vue](https://img.shields.io/badge/Vue-3-42b883?logo=vuedotjs&logoColor=white)
![ModSecurity](https://img.shields.io/badge/libmodsecurity-v3-1f6feb)
![OWASP CRS](https://img.shields.io/badge/OWASP%20CRS-4.x-000000)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%3A2025-000000)

**🌐 [專案介紹網站 →](https://jasoncheng7115.github.io/jt-waf-mgr/?lang=zh-TW)**

> 自架的 **nginx + libmodsecurity v3 + OWASP CRS 4** 網頁管理工具：看懂 WAF 做了什麼；透過「證據檢查、沙箱測試、人員核准」
> 的變更流程調整規則；由你自己的地端 LLM 檢視事件；重要事情發到 Teams、Telegram、Zulip、Slack、Discord、Nextcloud Talk、
> Email 或簽章 webhook。
>
> Jason Tools Co., Ltd. · 授權：AGPL-3.0

![總覽](docs/shots/zh-TW/overview.png)

---

## 為什麼需要 jt-waf-mgr？

libmodsecurity v3 沒有管理介面：規則、排除、封鎖都是設定檔，調整就得在正式的反向代理上讀 JSON 稽核記錄、手改檔案。
jt-waf-mgr 把稽核記錄變成看得懂的畫面，把每一次修改變成可以信任的流程：

- **看得懂發生了什麼**：封鎖 / 只記錄，依站台、攻擊類型、來源（含國家與網路業者）、規則與時間；「只因 CRS 分數被封鎖」
  的排在最前面，因為最可能是誤判。
- **安全地修改**：範本（排除、確定阻擋、遮蔽、外掛開關、專家模式原始規則）→ 靜態檢查（正規表示式、ReDoS）→ 存取記錄
  的證據 → 用正式設定加回歸樣本的拋棄式 nginx 沙箱 → 核准 → 小型 root 程式測試、reload、健康檢查，失敗自動還原 → 版本
  可一鍵退回。
- **讓模型幫忙，但不讓它自己決定**：排程分析用你自己的 OpenAI 相容 LLM 伺服器，對探測提出範圍很窄的封鎖、對誤判提出範圍
  最小的排除、發出警示；一切由程式驗證，放寬一律要人核准。
- **記錄可以信任**：雜湊鏈、只能追加的稽核記錄，錨點存在資料庫外與 syslog；發行檔有簽章；每個 nginx / ModSecurity /
  CRS 檔案都有指紋；提供 ISO/IEC 27001:2022、資通安全管理法、OWASP Top 10:2025 的合規對照。

## 功能

- **收集**：讀取 ModSecurity JSON 稽核記錄（支援 copytruncate 與改名輪替、過大與損壞的記錄）；密碼、token 等敏感欄位在
  **寫入之前**就遮蔽。
- **總覽與事件**：在時間軸上拖曳即可放大，或自訂最長 31 天的範圍；篩選條件存在網址；事件詳情列出每條命中的規則；一鍵草擬
  排除或封鎖。
- **WAF 判斷流程**：依目前的實際設定畫出一個請求在這些站台上怎麼被判定（各站台引擎、計分、門檻、排除、確定阻擋）。
- **規則**：每條規則標示來源（OWASP CRS 與版本、CRS 外掛、納管時匯入、人員 / API 權杖 / 事件分析提出的變更）、每日命中、
  語法高亮。
- **變更流程**：單筆變更或合成一筆（一次核准、一個版本、一次 reload）、上傳規則檔、證據、沙箱、健康檢查網址、核准規則
  （提出者不能核准；單人模式核准自己的放寬要重新輸入一次性驗證碼）、嚴格條件下的自動收緊、退回。
- **事件分析（地端 LLM）**：依規則看到的路徑分組候選；每批一次、以 JSON schema 限制格式的請求；由程式而不是模型決定提什麼
  （錨定且很窄的正規表示式，不可符合常見路徑、回歸樣本或組織自己在用的路徑；排除只限單一精確路徑、特定規則與欄位，核准
  要一次性驗證碼）；外部來源探測機密、備份或設定檔名，或同一位址掃過很多路徑，由程式直接判為探測；之前判為攻擊的路徑
  不會因為一次「誤判」就放寬；每次執行都有摘要。
  **AI 可能出錯，兩個方向都會**：模型只提供建議；放寬一律要人核准，只有通過所有檢查的收緊可以自動套用。
- **待處理警示**：可能沒被封鎖的攻擊、影響使用者的誤判、進行中的攻擊、設定被外部修改、完整性問題、套用或備份失敗——在核准者
  寫下處理說明之前一直保持開啟，並定期提醒。
- **通知**：Email（SMTP，純文字＋HTML）、Telegram、Microsoft Teams（Workflows / Adaptive Card）、Slack、Discord、Zulip、
  Nextcloud Talk 與通用 webhook（HMAC-SHA256 簽章）；事件 × 管道矩陣；每個管道都能發送測試；重試、上限與發送記錄。來自請求
  的內容永遠不會變成格式、連結或提及。
- **帳號**：scrypt 密碼、approver / admin 必須雙因素驗證、鎖定、含歷史與期限的密碼政策、帳號到期與審查；API 權杖有範圍與
  允許來源網段（權杖可以提案，永遠不能核准）。主機上的救援指令：`jt-waf-mgr user unlock | reset | passwd | disable | enable <名稱>`
  （reset 會清除 TOTP，下次登入必須改密碼）；每個動作都寫進稽核記錄。
- **完整性與合規**：系統檢查頁、合規頁、每日驗證過的備份與下載（需一次性驗證碼）、設定異動記錄與來源判斷（jt-waf-mgr、
  已登記的自動化或外部）。
- **介面**：English、繁體中文、日本語；淺色與深色；手機與平板；GeoIP（MaxMind GeoLite2，由獨立的受限程序下載），以及在頁面內繪製的請求來源世界地圖（不使用任何地圖服務）。

| | |
|---|---|
| ![事件](docs/shots/zh-TW/events.png) | ![WAF 判斷流程](docs/shots/zh-TW/waf-model.png) |
| ![事件分析](docs/shots/zh-TW/analysis.png) | ![通知](docs/shots/zh-TW/notifications.png) |
| ![待處理警示](docs/shots/zh-TW/alerts.png) | ![系統檢查](docs/shots/zh-TW/system-check.png) |

## 需求

- Debian 12 / 13 或 Ubuntu 24.04（22.04 的 libmodsecurity 套件太舊，要自行編譯 3.0.9 以上），**Python 3.11 以上，只用標準函式庫，不需要 pip 或任何套件**：可以離線安裝。
- nginx 加 ModSecurity-nginx 連接器、libmodsecurity 3.0.9 以上、OWASP CRS 4.x、`SecAuditLogFormat JSON`；稽核記錄請用
  `copytruncate` 輪替（libmodsecurity 在 reload 時不會重開檔案）。從全新的 nginx 開始，或還沒有 CRS 4：請看
  [ModSecurity 安裝手冊](docs/MODSECURITY.zh-TW.md)。沒有站台規則檔也能納管（會在 CRS 規則前後加入空的受管理檔案）。
- 選用：網路上的 OpenAI 相容 LLM 伺服器（llama.cpp、vLLM、Ollama…）供事件分析；GeoIP 需要 MaxMind 帳號。

## 安裝

```sh
openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-0.4.18.tar.gz.sig jt-waf-mgr-0.4.18.tar.gz
tar xzf jt-waf-mgr-0.4.18.tar.gz && cd jt-waf-mgr-0.4.18
sudo ./install.sh                             # 先驗證每個檔案與發行檔簽章
sudo jt-waf-mgr check                         # 解析 nginx / ModSecurity 設定
sudo jt-waf-mgr user add alice --role admin   # 印出臨時密碼
```

加上管理介面的 vhost（`/etc/jt-waf-mgr/nginx-vhost.conf.example`：只允許內部網路，轉到 `127.0.0.1:8095`），`nginx -t`、
reload，登入後改密碼並設定雙因素驗證。營運設定（GeoIP、LLM、分析、通知、網路、政策）都在網頁上設定；
`/etc/jt-waf-mgr/config.toml` 只放程式啟動需要的項目。

要讓 jt-waf-mgr 修改規則：啟用套用程式（`sudo ./install.sh --enable-apply`）、設定健康檢查網址，再到「規則 → 受管理的
規則」納管現有規則檔（由 admin 核准，跟一般變更一樣）。在那之前不會動到 nginx。

### 升級

```sh
sudo ./upgrade.sh --check     # 只做所有檢查，不改任何東西
sudo ./upgrade.sh             # 備份、切換、檢查；任何一步失敗自動還原
sudo ./upgrade.sh --rollback  # 之後需要時：回到升級前的版本（與資料庫）
sudo jt-waf-mgr doctor        # 隨時查看健康狀態
```

升級會用已安裝的程式與釘選的金鑰驗證新版本、有變更正在套用時拒絕升級、在 `/var/backups/jt-waf-mgr/` 保留備份，並把每次
升級（與還原）寫進稽核記錄。

### 移除

```sh
sudo ./uninstall.sh           # 移除服務與程式，保留資料與設定
sudo ./uninstall.sh --purge   # 連同 /var/lib/jt-waf-mgr、/etc/jt-waf-mgr 與 jtwaf 帳號一併移除
```

不會動到 nginx 設定：管理介面的 vhost 請自行移除。如果已經納管規則檔，`/etc/nginx/modsec/jt-waf-mgr/` 裡的受管理檔案
會保留，nginx 照常載入；之後請自行維護。

## 安全（OWASP Top 10:2025）

請見 [SECURITY.md](SECURITY.md) 與 [docs/COMPLIANCE.zh-TW.md](docs/COMPLIANCE.zh-TW.md)。發現弱點請私下回報。

- 網頁服務只聽 loopback、以非特權帳號執行、不會對外連線；只有套用程式是 root，它會重新驗證每個請求（只允許特定指令、
  檢查碼、磁碟上不能有手動修改），也只寫受管理的檔案。GeoIP 下載、LLM 分析與通知各自在受限的一次性 unit 裡執行。
- 嚴格的 CSP（不允許 `unsafe-inline`）；來自請求的內容（網址、User-Agent、命中資料、模型的文字）一律以純文字顯示。
- 敏感值在進資料庫前就遮蔽；設定裡的金鑰只能寫入、不能讀回。
- A01：角色 viewer / operator / approver / admin、API 權杖範圍與來源網段；權杖永遠不能核准。
- A04 / A07：scrypt、可防重放的 TOTP、鎖定、敏感操作的一次性驗證碼（限制錯誤次數）。
- A08：發行清單簽章，由安裝程式、服務與套用程式檢查；雜湊鏈稽核記錄。
- A09：每個寫入都有稽核，也送到 syslog（一行 JSON，控制字元已跳脫）。
- 每次發版都要通過測試計畫（[TEST_PLAN.md](TEST_PLAN.md)）：單元測試、每一頁的瀏覽器測試、每個路由的安全檢測、OWASP ZAP
  主動掃描、獨立審查、升級與還原測試。

## 技術

| 層 | 選擇 |
|------|--------|
| 後端 | Python 3.11+ 標準函式庫（http.server、sqlite3、hashlib.scrypt、tomllib、urllib、smtplib） |
| 資料庫 | SQLite（WAL），稽核表以觸發器限制只能追加 |
| 前端 | Vue 3 · Vite · 自寫 i18n（不在執行期編譯，符合 CSP）· Iconoir 圖示 |
| WAF | nginx · libmodsecurity v3 · ModSecurity-nginx · OWASP CRS 4 |
| 部署 | systemd unit（服務、套用、GeoIP、分析、通知）；不需要 Docker |

## 目錄結構

```
jt-waf-mgr/
├── jtwafmgr/            # 程式本體（收集、網頁 API、變更流程、套用、分析、通知、完整性）
│   ├── collector/       # ModSecurity 稽核記錄讀取
│   ├── web/             # HTTP 伺服器與路由
│   └── static/          # 建置好的網頁介面
├── frontend/            # 網頁介面的 Vue 3 原始碼
├── deploy/              # systemd unit、nginx 範例、發行公鑰、Wazuh 規則草稿、ZAP 基準
├── docs/                # 規格、API 契約、合規對照、專案網站
├── tests/               # 單元與整合測試（只用合成資料）
├── tools/               # 建置、發行、preflight、瀏覽器測試、安全檢測、ZAP 掃描
├── install.sh · upgrade.sh · uninstall.sh
└── TEST_PLAN.md · TEST_CHECKLIST.md · SECURITY.md · CHANGELOG.md
```

## 授權

AGPL-3.0。如果你把修改過的版本作為網路服務提供，必須讓使用者取得原始碼（未修改版本由頁尾連結提供）。
