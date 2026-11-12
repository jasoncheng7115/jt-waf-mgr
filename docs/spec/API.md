# jt-waf-mgr 介接 API（草案 v0.1，2026-11-10）

> 本文件可公開。機器可讀版本見 `openapi.yaml`（草案，實作時以程式產生的 OpenAPI 為準）。

## 1. 原則

- 基底路徑 `/api/v1`，JSON（UTF-8），時間一律 RFC 3339（含時區）。
- **v1 只做加法**：新增欄位與端點不升版；刪改要先標示 `Deprecation`／`Sunset` 標頭至少一個次版本。
- 給人用的介面與給系統用的 API 是同一套端點；人走 OIDC session，系統走 token。
- 所有清單端點用游標分頁：`?limit=`（預設 100，上限 1000）＋回應的 `next_cursor`。
- 錯誤格式固定：`{"error": {"code": "string", "message": "string", "details": {...}}}`；HTTP 狀態碼照常使用（400、401、403、404、409、422、429、501）。
- 速率限制：每個 token 可設定，超過回 429 與 `Retry-After`。
- 敏感欄位在 API 回應中一律已遮蔽（與介面相同），API 沒有「看原文」的選項。

## 2. 認證與權限

### 2.1 API token

- 由管理者在介面建立，格式 `jwm_<id>_<secret>`；只在建立當下顯示一次，資料庫只存雜湊。
- 每個 token 綁定：名稱（例如 `jt-ipam`）、scope 清單、可用來源位址（CIDR，選填但建議設定）、到期日（選填）。
- 傳遞方式：`Authorization: Bearer <token>`。
- 每次使用都寫稽核紀錄（token 名稱、來源、端點、結果）。

### 2.2 OIDC client credentials（選用）

- 若站台的 IdP 支援，可改用 client credentials 取得的 access token；scope 由 IdP 的角色或 claim 對應。

### 2.3 Scope

- `status:read`：狀態與健康。
- `events:read`：事件、統計、匯出。
- `rules:read`：規則、站台清單。
- `changes:read`：變更與歷史。
- `changes:propose`：提出變更（**只能提出，永遠不能核准**；放寬類一定進待核准）。
- `ipblocks:write`：新增與移除暫時封鎖（受第 5 節的限制）。
- `lookups:read`：IP 查詢。
- `webhooks:manage`：管理自己的 webhook 訂閱。
- 沒有任何 token scope 可以核准變更、改設定或管理 token；這些只能由人在介面上做。

## 3. 端點一覽

### 狀態

- `GET /api/v1/status`（`status:read`）
  - 回傳：版本、引擎模式（全域 DetectionOnly／On）、外部超過門檻阻擋是否開啟、CRS 版本與偏執等級、門檻、最後一次套用（時間、變更 ID、結果）、記錄收集延遲、受管理檔案是否被手動改過、nginx 與模組版本是否一致。

### 事件

- `GET /api/v1/events`（`events:read`）
  - 篩選：`since`、`until`、`host`、`path_prefix`、`src_ip`（可 CIDR）、`country`（兩碼國家代碼，外部來源依 GeoIP）、`rule_id`、`outcome`（`blocked`／`logged`）、`decided_by`（`confident`／`score`／`fallback`）、`origin`（`external`／`internal`）。
- `GET /api/v1/events/{event_id}`（`events:read`）
- `GET /api/v1/events/stats`（`events:read`）
  - `group_by=host|rule|src_ip|family|hour`，`since`／`until`。
- `GET /api/v1/events/export`（`events:read`）
  - 給記錄封存系統：`?cursor=`（第一次不帶）回傳 `application/x-ndjson`（可 `Accept-Encoding: gzip`），每行一個事件；回應標頭 `X-Next-Cursor`、`X-Content-SHA256`（未壓縮內容的雜湊）。游標保證不漏不重（以單調遞增的內部序號實作）。

### 規則與站台

- `GET /api/v1/rules`（`rules:read`）：受管理與未受管理的規則，含類型、範圍、說明、啟用狀態、命中統計。
- `GET /api/v1/rules/{rule_id}`（`rules:read`）
- `GET /api/v1/rules/{rule_id}/hits`（`rules:read`）：依日統計。
- `GET /api/v1/vhosts`（`rules:read`）：站台清單與 WAF 狀態（啟用、阻擋模式、不經 WAF 的路徑、本體上限、存取限制）。

### 變更

- `GET /api/v1/changes`、`GET /api/v1/changes/{change_id}`（`changes:read`）
- `POST /api/v1/changes`（`changes:propose`）
  - 本體：`{"kind": "exclusion|confident_block|redaction|plugin", "spec": {...與 SPEC 5.3 樣板相同的欄位...}, "reason": "string", "evidence_ref": {"event_ids": [...]}, "tests": [...選填...]}`
  - 回應 202：`{"change_id": "...", "direction": "tighten|loosen", "state": "validating"}`；之後由流程推進到 `pending_approval`／`rejected`／`applied`。
  - 專家模式（raw）不能透過 API 提出。
- 核准、拒絕、套用、還原：**沒有 token 用的端點**（只在介面上由人操作）。

### 暫時封鎖 IP

- `GET /api/v1/ip-blocks`（`rules:read`）
- `POST /api/v1/ip-blocks`（`ipblocks:write`）
  - 本體：`{"cidr": "203.0.113.7/32", "ttl_seconds": 3600, "reason": "string", "source": {"system": "jt-wazuh-mgr", "ref": "alert-id"}}`
  - 回應 202：`{"block_id": "...", "state": "queued", "expires_at": "..."}`
- `DELETE /api/v1/ip-blocks/{block_id}`（`ipblocks:write`，只能刪自己 token 建立的；刪除屬於放寬，但「提早結束自己建立的暫時封鎖」視為例外，不需核准，會記錄）
- 實作：寫入 `ip-blocks.txt`，由一條系統規則以 `@ipMatchFromFile` 比對外部來源後打開引擎並拒絕；批次合併（例如每 60 秒最多一次 reload）。

### 查詢

- `GET /api/v1/lookups/ip/{ip}`（`lookups:read`）
  - 回傳：這個位址最近 7／30 天的請求數、被擋數、命中的規則與站台、首次與最後出現時間、目前是否被暫時封鎖。給 IPAM 的裝置頁與 SIEM 告警下鑽用。

### Webhook

- `GET/POST/DELETE /api/v1/webhooks`（`webhooks:manage`，只能管自己 token 的訂閱）
- 事件類型：
  - `change.pending_approval`、`change.applied`、`change.rolled_back`、`change.rejected`
  - `ipblock.added`、`ipblock.expired`
  - `fp.suspected`：只靠分數擋下的外部請求（可能誤擋），彙整後送出
  - `block.burst`：某來源或某規則在短時間內大量命中（門檻可設定）
  - `config.drift`：受管理檔案被手動修改
  - `crs.update_available`
  - `health.degraded`：記錄收集停止、套用失敗、模組版本不符
- 簽章：`X-JTWAF-Signature: t=<unix>,v1=<hex(HMAC-SHA256(secret, t + "." + body))>`；接收端應檢查時間差 ≤ 300 秒。
- 重試：指數退避，最多 24 小時；失敗與停用都記錄。

## 4. 輸出的稽核事件（給 SIEM）

每個動作一行 JSON 到 syslog，program name `jt-waf-mgr`：

```json
{"jt_waf_mgr": {"v": 1, "action": "change.applied", "change_id": "c_01H...", "direction": "loosen",
  "kind": "exclusion", "rule_id": 10130, "host": "app.example.com", "actor": "alice",
  "actor_type": "user", "approved_by": "bob", "result": "ok", "ts": "2026-11-10T10:21:00+08:00"}}
```

- `action`：`login`、`login.failed`、`change.proposed`、`change.approved`、`change.rejected`、`change.applied`、`change.apply_failed`、`change.rolled_back`、`ipblock.added`、`ipblock.removed`、`token.created`、`token.revoked`、`settings.changed`、`config.drift`。
- 所有字串欄位寫入前跳脫換行與控制字元。
- Wazuh 端的解讀規則由 jt-wazuh-mgr 的 jt-modsecurity 套件提供（另一個專案；預計：放寬類套用、套用失敗、還原、手動修改、token 建立為較高等級）。

## 5. 暫時封鎖的限制（防止被濫用）

- 拒絕：內網位址、設定的允許清單（例如 CDN、監控、合作夥伴）、管理介面本身的來源、`/0`～`/15` 這類過大的範圍（上限可設定，預設 IPv4 /24、IPv6 /48）。
- 每個 token：同時有效數量上限、每小時新增上限、TTL 上限（預設 7 天）。
- 全域：同時有效封鎖總數上限；超過就拒絕並發 `health.degraded`。
- 來源是 CDN 的站台：用戶端位址要是經過 real-ip 還原後的位址；工具會檢查站台的 real-ip 設定，未設定時警告「封鎖會打到 CDN 節點」。

## 6. 介接情境

### 6.1 jt-wazuh-mgr（Wazuh 管理工具）

- **看**：在介面放一張「WAF 狀態」卡片（`GET /status`、`GET /events/stats`），點進去開 jt-waf-mgr。
- **下鑽**：Wazuh 告警的來源 IP → `GET /lookups/ip/{ip}`，顯示這個位址在 WAF 上做了什麼。
- **聯動封鎖**（選用，預設關）：Wazuh 偵測到跨服務的暴力破解等高信心事件時，呼叫 `POST /ip-blocks`（短 TTL），結果回寫到告警備註。
- **稽核**：Wazuh 收 jt-waf-mgr 的 syslog 稽核事件，由 jt-modsecurity 套件的規則告警。
- 建議 token：`status:read`、`events:read`、`lookups:read`，需要聯動時再加 `ipblocks:write`。

### 6.2 jt-ipam（IP 位址管理）

- **jt-waf-mgr 用 jt-ipam**：事件上的內網位址顯示主機名稱與擁有者（呼叫 jt-ipam 自己的 API，jt-ipam 端建一個唯讀 token）；內網網段、已知掃描器（jt-ipam 的掃描代理）可以從 jt-ipam 同步，減少手動設定。
- **jt-ipam 用 jt-waf-mgr**：IP 或裝置頁顯示 `GET /lookups/ip/{ip}`；「IP 變更評估」把「這個位址在 WAF 規則裡被引用」（例如排除規則的來源範圍、允許清單）列為影響項目，可用 `GET /rules`（篩選 `references_ip=`，P3 新增）取得。
- 建議 token：`lookups:read`、`rules:read`。

### 6.3 jt-glogarch（Graylog Open 記錄封存）

- **封存 WAF 事件與變更紀錄**：jt-glogarch 定期呼叫 `GET /events/export`（游標、gzip、SHA-256）取走事件，連同 `GET /changes` 一起封存；封存檔沿用 jt-glogarch 的完整性驗證。
- **或經 Graylog**：WAF 事件本來就可以經 Vector／GELF 進 Graylog，由 jt-glogarch 封存 Graylog 的串流；這種情況下 jt-waf-mgr 只需要把**稽核事件**也送進 Graylog（syslog 或 GELF 輸出，P3）。
- **歷史證據**：jt-waf-mgr 本機只保留 30 天事件；做證據檢查時若需要更早的資料，可選擇呼叫 jt-glogarch 的記錄搜尋（介面待雙方確認，P4）。
- 建議 token：`events:read`、`changes:read`。

## 7. 預留

- **MCP 伺服器**（與 jt-ipam 相同的作法）：讓 AI 助手唯讀查詢事件與規則、提出變更（只能進待核准）。注意事件內容是攻擊者可控的文字，MCP 回應要標示為「不可信資料」。P4 以後再評估。
- 多台 WAF 聚合：每台各一份 jt-waf-mgr，由上層呼叫各台 API 彙整；v1 的 API 不做跨台。
