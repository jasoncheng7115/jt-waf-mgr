# API 介接手冊

[English](API.md) · **繁體中文** · [日本語](API.ja.md)

這份手冊寫給要把其他系統接上 jt-waf-mgr 的人：從 SIEM 拉 WAF 事件、從 SOAR 劇本提出封鎖規則，或是自己寫的腳本。
網頁介面用的是同一套端點，只是以登入後的 session 呼叫；介接系統則用 **API 權杖**。以下說明的都是權杖能做的事。

> **API 權杖可以提出變更，但永遠不能核准。** 核准、退回、取消、還原都由人在網頁介面上操作。權杖提出的變更與其他人
> 提出的一樣，要經過全部檢查。

所有範例都用虛構的值：`waf.example.com`、192.0.2.0/24、198.51.100.0/24、203.0.113.0/24 的位址，以及假的權杖。

## 1. 基本規則

- **基底網址**：`https://<jt-waf-mgr 主機>/api/v1`，例如 `https://waf.example.com/api/v1`。jt-waf-mgr 只聽
  127.0.0.1，前面是 nginx；請透過那個 nginx 站台呼叫。
- **JSON**：回應是 UTF-8 的 JSON（`application/json; charset=utf-8`），另有註明者除外（NDJSON 匯出、規則檔下載）。
  有本文的請求必須送 `Content-Type: application/json`，本文是 JSON 物件，否則回 415 或 400。本文預設上限 1 MiB
  （超過回 413 `payload_too_large`）。
- **版本**：主版本在路徑上（`/api/v1`）。`GET /meta` 回傳程式版本。之後會陸續增加欄位：不認得的欄位請忽略。
- **時間**：回應一律是 RFC 3339，帶伺服器的本地時區，精確到秒，例如 `2026-11-13T15:13:27+08:00`。`since`、`until`
  等參數接受 RFC 3339（`Z` 或時區）；沒有時區的時間或只有日期時，以伺服器本地時間解讀。
- **分頁**：清單接受 `limit` 與 `cursor`，回傳 `next_cursor`（字串，最後一頁是 `null`）。把 `next_cursor` 原樣當成
  `cursor` 傳回即可。除非另有註明，清單都是新的在前。
- **快取與壓縮**：每個 API 回應都帶 `Cache-Control: no-store`；送 `Accept-Encoding: gzip` 可以讓較大的回應壓縮。
- **敏感資料**：請求資料中的密碼等欄位在寫入資料庫前就已遮蔽，API 沒有看原文的選項。

## 2. 認證

### 2.1 建立權杖

- 只有**管理者**能建立權杖：網頁介面的**管理 > API 權杖**（`/admin/tokens`），「建立權杖」區塊。
- 填寫名稱（例如呼叫端系統的名稱）、允許的來源位址、到期日（選填），並勾選一個或多個 scope。
- 權杖只在建立當下顯示**一次**，請立即存進呼叫端的機密儲存區。資料庫只存雜湊；遺失的權杖無法再取得，只能撤銷後重建。
- 權杖的格式是 `jwm_<12 個字元>_<密鑰>`。範例用的假權杖是
  `jwm_example00000_EXAMPLE-not-a-real-token`。
- 同一頁會列出所有權杖（scope、來源、到期日、最後使用時間），也可以撤銷。撤銷立即生效。
- 用權杖提出的變更歸屬於建立該權杖的管理者，這位管理者不能核准這些變更（見 6.3）。

### 2.2 Scope

權杖可以有下列一個或多個 scope，沒有其他種類。

- `status:read`：`GET /status`。
- `events:read`：事件、事件統計、時間軸、總覽、NDJSON 匯出。
- `rules:read`：規則、規則命中、站台（vhost）、CRS 狀態與更新、WAF 判斷流程、受管理規則檔。
- `lookups:read`：IP 查詢與 GeoIP 查詢。
- `changes:read`：變更、版本、警示、事件分析記錄、回歸測試樣本。
- `changes:propose`：提出變更（`POST /changes`、`POST /changes/preview`、`POST /rules/toggle`），永遠不能核准。
- `blocks:read`：列出暫時封鎖的 IP（`GET /blocks`）。
- `blocks:write`：新增、延長、解除這個權杖自己的暫時封鎖（只能單一位址）。

每個權杖只給需要的 scope。只讀事件的 SIEM 給 `events:read`；會提出封鎖規則的劇本給 `changes:propose` 與
`changes:read`。

### 2.3 來源限制

- 「允許的來源位址」是 CIDR 清單，例如 `192.0.2.10/32, 198.51.100.0/24`；空白表示不限來源。強烈建議設定。
- 檢查的是 jt-waf-mgr 看到的來源位址：本機 nginx 設定的 `X-Real-IP`（只接受受信任的代理提供）。請確認呼叫端直接連到
  這個 nginx，不要經過另一層會隱藏來源位址的代理。
- 從其他位址呼叫會得到 403 `token_source_not_allowed`，並寫入稽核記錄。

### 2.4 到期

- 選填。沒有到期日的權杖會一直有效，直到被撤銷。
- 已到期、已撤銷、不存在或格式錯誤的權杖都回 401 `invalid_token`。

### 2.5 傳送權杖

放在 `Authorization` 標頭，使用 `Bearer`。權杖不需要 cookie，也不需要 CSRF 標頭。

```sh
TOKEN='jwm_example00000_EXAMPLE-not-a-real-token'
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/status
```

每次用權杖呼叫都會寫一筆稽核記錄（`token.used`；被拒時是 `token.denied` 並附原因），內容有權杖名稱、來源位址與端點。

### 2.6 Session（參考）

網頁介面以帳號、密碼與一次性密碼登入，取得 session cookie，每個會改變狀態的請求都送 `X-CSRF-Token`。介接系統不要用
session，請用權杖。

## 3. 錯誤與限制

所有錯誤的格式都相同：

```json
{"error": {"code": "token_source_not_allowed", "message": "token source not allowed", "details": {}}}
```

程式請依 `code` 判斷；`message` 是給人看的；`details` 補充內容（例如哪個欄位不對）。常見的代碼：

- **400**：`bad_request`（參數格式錯誤，例如 `limit must be a number`）、`reason_required`、`invalid_op`、
  `invalid_kind`、`invalid_tests`、`no_effect`（例如停用一個本來就停用的項目）。
- **401**：`not_authenticated`（沒有送權杖）、`invalid_token`（不存在、格式錯誤、已撤銷或已到期）。
- **403**：`forbidden` 且訊息是 `token lacks scope`（`details.scope` 是需要的 scope；任何權杖都不能呼叫的端點是
  `null`）；`forbidden` 且訊息是 `not available to API tokens`（管理與帳號端點）；`token_source_not_allowed`；
  `raw_admin_only`（專家模式規則，見 4.4）。
- **404**：`not_found`；`item_not_found`（`item_id` 指定的受管理項目不存在）。
- **405**：`method_not_allowed`。
- **409**：`not_adopted`（jt-waf-mgr 還沒納管站台的規則檔，無法提出變更）、`invalid_state`（`details.state`）、
  `rule_id_in_use`、`id_range_full`、`nothing_to_change`。
- **413** `payload_too_large`；**415**（代碼 `bad_request`）：本文不是 `application/json`。
- **422**：`invalid_spec`（`details.field` 與 `details.reason`，例如 `regex` 與 `too_broad`）、`invalid_bundle`
  （`details.index`、`details.limit` 或 `details.reason`）、`invalid_rule_ids`、`invalid_group`、`invalid_scope`、
  `scope_required`、`invalid_action`。
- **429** `too_many_attempts`，附 `Retry-After` 標頭：登入與一次性密碼嘗試太多次。請等待標頭指定的秒數。
- **500** `internal_error`。

**速率限制**：這一版沒有針對每個權杖的請求速率限制。輪詢請保持適當間隔（下面的範例每 10 秒一次），萬一收到 429 就依
`Retry-After` 等待。jt-waf-mgr 前面的反向代理可能另有限制。

## 4. 端點

以下路徑都相對於 `/api/v1`。「Scope」是權杖需要的 scope。

### 4.1 系統資訊與狀態

**`GET /meta`**：不需認證。名稱、版本、原始碼網址、節點代號。

```sh
curl -sS https://waf.example.com/api/v1/meta
```
```json
{"name": "jt-waf-mgr", "version": "0.4.22", "source_url": "https://...",
 "sso_enabled": false, "node_id": "waf1", "login_notice": "", "password_policy": {"min_length": 12, "...": "..."}}
```

**`GET /status`**：scope `status:read`。引擎模式、CRS 設定，以及讀取 ModSecurity 稽核記錄的收集程式狀態（監控時看
`collector.running`、`lag_seconds`、`last_event_at`）。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/status
```
```json
{"version": "0.4.22", "node_id": "waf1", "engine_mode": "On", "external_threshold_block": true,
 "crs": {"version": "4.30.0", "paranoia_level": 1, "blocking_paranoia_level": 1, "inbound_threshold": 5,
         "outbound_threshold": 4},
 "collector": {"running": true, "error": null, "last_event_at": "2026-11-13T15:13:27+08:00", "lag_seconds": 0,
               "parse_errors": 0, "oversized": 0, "insert_errors": 0, "events_total": 1234, "...": "..."},
 "nginx": {"version": "1.22.1", "module_mismatch": null}}
```

### 4.2 事件

**`GET /events`**：scope `events:read`。事件清單，新的在前。參數（全部選填）：

- `since`、`until`：RFC 3339。
- `host`（完全相符）、`path_prefix`、`q`（路徑中包含的文字）。
- `src_ip`：單一位址，或網段如 `203.0.113.0/24`。
- `country`：兩碼國家代碼；只看外部來源，需要 GeoIP。
- `rule_id`：有命中這條規則的事件。
- `outcome`：`blocked` 或 `logged`。`origin`：`external` 或 `internal`。
- `decided_by`：`confident`、`score`、`fallback` 或 `other`。
- `family`：`protocol`、`lfi`、`rfi`、`rce`、`php`、`generic`、`xss`、`sqli`、`session`、`java`、`scanner`、
  `method`、`body`、`data_leak`、`local` 或 `other`。
- `limit`（預設 100，最多 1000）、`cursor`。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" \
  'https://waf.example.com/api/v1/events?outcome=blocked&origin=external&since=2026-11-13T00:00:00%2B08:00&limit=1'
```
```json
{"items": [{"id": 1, "ts": "2026-11-13T15:13:27+08:00", "host": "app.example.com", "method": "GET",
            "path": "/.env", "query": "", "src_ip": "203.0.113.7", "origin": "external", "status": 403,
            "outcome": "blocked", "decided_by": "confident", "rule_ids": [10205, 949110], "families": ["local"],
            "message": "jt confident block: dotenv probe", "local_rule_ids": [10205], "src_geo": null}],
 "next_cursor": "1"}
```

**`GET /events/{id}`**：scope `events:read`。單一事件，含規則命中明細、異常分數與連線資訊。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/events/1
```
```json
{"id": 1, "...": "清單項目的欄位，另外加上：", "unique_id": "...", "http_version": "1.1",
 "engine": "Enabled", "client_port": 51234, "server_port": 443, "anomaly_score": null,
 "matches": [{"rule_id": 10205, "message": "...", "severity": "CRITICAL", "data": "", "match": "...",
              "tags": [], "file": "...", "line": 50, "family": "local", "local": true}],
 "truncated": false}
```

**`GET /events/export`**：scope `events:read`。給 SIEM 的增量匯出，格式是 NDJSON（每行一筆完整事件），**舊的在前**。
`cursor` 是你已有的最後一筆事件 id（第一次用 0）；`limit` 預設 1000，最多 5000。回應標頭有 `X-Next-Cursor`（存起來給
下一次用）與 `X-Content-SHA256`（本文的 SHA-256）。本文是空的表示已經追上。這個端點不套用篩選條件。

```sh
curl -sS -D headers.txt -H "Authorization: Bearer $TOKEN" \
  'https://waf.example.com/api/v1/events/export?cursor=0&limit=1000' > events.ndjson
grep -i '^x-next-cursor' headers.txt
```

**`GET /events/stats`**：scope `events:read`。依 `group_by` 分組計數：`host`（預設）、`rule`、`src_ip`、`family`
或 `hour`，範圍是 `since` 到 `until`（預設最近 24 小時）。

```json
{"group_by": "rule", "items": [{"key": "10205", "msg": "...", "family": "local", "blocked": 1, "logged": 0}]}
```

**`GET /events/timeline`**：scope `events:read`。篩選條件與 `/events` 相同；`since`、`until` 預設最近 7 天，最多 31 天
（被縮短時 `clamped: true`）。7 天以內每小時一格，超過則每天一格。

**`GET /overview`**：scope `events:read`。總覽頁的數字：`range` 是 `24h`（預設）、`7d`，或 `custom` 搭配 `since` 與
`until`（1 小時到 31 天），另可加事件篩選條件。回傳 `totals`、`previous`（前一個同長度區間）、`timeline`、`by_host`、
`by_family`、`by_src`、`by_rule`、`by_country`、`by_asn` 等。

### 4.3 警示

警示是需要人處理的事（可能已經得手的攻擊、疑似誤判、完整性問題、套用失敗等）。

- **`GET /alerts`**：scope `changes:read`。`state` 是 `open` 或 `handled`；`limit`（預設 50，最多 200）；`cursor`。
  回應附 `counts`。
- **`GET /alerts/counts`**：scope `changes:read`。`{"open": 3, "critical": 1}`。
- **`GET /alerts/{id}`**：scope `changes:read`。

`kind` 是 `attack_in_progress`、`attack_passed`、`false_positive`、`integrity`、`config_outside`、`apply_failed`、
`backup_failed`、`auth_attack`、`crs_update`、`other` 其中之一；`severity` 是 `critical` 或 `warning`。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" 'https://waf.example.com/api/v1/alerts?state=open&limit=20'
```
```json
{"items": [{"id": 12, "created_at": "2026-11-13T09:00:04+08:00", "last_seen": "2026-11-13T12:00:03+08:00",
            "source": "analyst", "kind": "attack_passed", "severity": "critical", "count": 2,
            "details": {"run_id": 40, "...": "..."}, "link": "...", "state": "open", "handled_by": null,
            "handled_at": null, "note": null, "summary": "..."}],
 "next_cursor": null, "counts": {"open": 1, "critical": 1}}
```

把警示標記為已處理，要由核准者在網頁介面上操作。

### 4.4 變更

變更是一個提案：在 jt-waf-mgr 的受管理規則檔中新增、修改、停用、啟用或刪除一條規則，或一次處理多條（整批）。提出變更
的前提是 jt-waf-mgr 已經納管站台的規則檔（由管理者做一次）；在那之前所有提案都回 409 `not_adopted`。

**`POST /changes/preview`**：scope `changes:propose`。只產生規則文字，不建立任何東西。提出前可以先用它驗證 `spec`。
驗證錯誤以 200 回傳，`ok: false`。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind": "confident_block", "spec": {"target": "path", "regex": "^/\\.env$", "msg": "dotenv probe"}}' \
  https://waf.example.com/api/v1/changes/preview
```
```json
{"ok": true, "rule_id": 10204, "rule_text": "SecRule REQUEST_FILENAME \"@rx ^/\\.env$\" ...",
 "placement": "before", "direction": "tighten"}
```
```json
{"ok": false, "field": "regex", "reason": "matches_empty", "details": {}}
```

**`POST /changes`**：scope `changes:propose`。本文：

- `op`：`add`（預設）、`modify`、`disable`、`enable`、`delete` 或 `bundle`。
- `kind`：`add` 時是 `confident_block`、`exclusion`、`redaction`、`plugin` 或 `raw`。
- `spec`：該種類的欄位（見下）。`modify` 要給完整的新 spec。
- `item_id`：`modify`、`disable`、`enable`、`delete` 時，受管理項目的 id（`GET /managed` 的 `items[].id`）。
- `reason`：必填，最多 2000 字，會顯示給核准者。
- `tests`：選填，最多 50 個在沙箱裡實際送出的請求：`{"host", "path", "expect": 200 | 403,
  "source": "external" | "internal", "method"?, "headers"?, "body"?}`。

回應 202 與變更編號；檢查在背景進行：

```json
{"change_id": 2, "direction": "tighten", "state": "checking", "rule_id": 10204}
```

`direction` 是 `tighten`（收緊：封鎖或檢查更多）或 `loosen`（放寬：更少）。無法判斷的一律視為放寬。放寬一定要人核准。

**種類 `confident_block`**（確定阻擋：確定是攻擊的請求直接封鎖，不看異常分數）：

- `target`：`path`（預設；URL 解碼、正規化、轉小寫）、`uri`（路徑加查詢字串，轉小寫）、`ua`（User-Agent）、`host`，
  或 `header`（這時用 `header` 指定名稱，例如 `X-Api-Version`）。
- `regex`：必填，最多 1000 字，不可有雙引號或換行。比對到空字串（`matches_empty`）、幾乎比對到所有一般請求
  （`too_broad`），或可能造成災難性回溯（`redos_shape`、`redos_runtime`）時會被拒絕。
- `msg`：必填，最多 100 字，不可有引號或反斜線。規則訊息會是 `jt confident block: <msg>`。
- `exceptions`：選填，最多 10 個路徑的正規表示式，符合者永不封鎖。
- `host`：選填，`{"mode": "any"}`（預設）、`{"mode": "exact", "value": "app.example.com"}`（可用
  `*.example.com`），或 `{"mode": "regex", "value": "..."}`。
- `reference`：選填，最多 200 字（工單或資安通報編號）。
- `source`：`external`（預設；內部位址永不封鎖）或 `all`（內部位址也封鎖，但排除已知掃描器）。

**種類 `exclusion`**（排除：讓規則在造成誤判的地方不觸發；一律是放寬）：

- `host` 與 `path` 至少一個：`path` 是 `{"mode": "exact" | "prefix" | "regex", "value": "/search"}`。
- `method`：選填，例如 `POST`。`source`：`all`（預設）、`external` 或 `internal`。
- `action`：`remove_target_by_id`（預設；需要 `rule_ids` 與 `targets`）、`remove_target_by_tag`（`tag` 與
  `targets`）、`remove_rule`（`rule_ids`）、`remove_tag`（`tag` 與 `confirm_tag: true`）、`score_only`，或
  `body_processor`（`body_processor` 是 `JSON`、`XML`、`URLENCODED` 或 `MULTIPART`）。
- `rule_ids`：最多 20 個。`targets`：最多 20 個 ModSecurity 變數，例如 `ARGS:q`、`REQUEST_COOKIES:session`。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "kind": "exclusion", "reason": "search box triggers 941100 for normal users",
  "spec": {"host": {"mode": "exact", "value": "app.example.com"}, "path": {"mode": "exact", "value": "/search"},
           "action": "remove_target_by_id", "rule_ids": [941100], "targets": ["ARGS:q"]}}' \
  https://waf.example.com/api/v1/changes
```
```json
{"change_id": 3, "direction": "loosen", "state": "checking", "rule_id": 10120}
```

**種類 `redaction` 與 `plugin`**：`redaction` 用 `fields`（最多 30 個參數名稱，不檢查，因此永遠不會被複製進稽核記錄），
可加 `host`、`path`；`plugin` 用 `plugin`（CRS 外掛名稱）與必填的 `host`，為單一站台啟用外掛。

**種類 `raw`**（專家模式：照原樣寫的 SecRule）：新增或修改專家模式規則**只限管理者在網頁介面上操作**，權杖會得到 403
`raw_admin_only`。（權杖可以停用、啟用或刪除既有的專家模式項目。）

**整批**（`"op": "bundle"`）：多個操作合成一筆變更，一起檢查、核准、套用（一個版本、一次 reload、一次還原）。`ops` 放
1 到 100 個 `{"op", "kind", "spec", "item_id"}`，其中確定阻擋最多 20 個。只有每個操作都是收緊時，整批才算收緊。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "op": "bundle", "reason": "probes seen from 203.0.113.0/24 this morning",
  "ops": [{"op": "add", "kind": "confident_block", "spec": {"regex": "^/wp-config\\.php", "msg": "wp-config probe"}},
          {"op": "add", "kind": "confident_block", "spec": {"regex": "^/\\.git/", "msg": "git probe"}}]}' \
  https://waf.example.com/api/v1/changes
```
```json
{"change_id": 4, "direction": "tighten", "state": "checking", "rule_id": null}
```

**`POST /rules/toggle`**：scope `changes:propose`。把多條規則或整個分類一次停用或啟用，合成一筆變更：
`{"action": "disable" | "enable", "rule_ids": [...]（最多 300 個）或 "group": {"source": "crs" | "local", "key":
"<攻擊類別或分類>"}, "scope": {"mode": "hosts", "hosts": ["app.example.com"]}, "reason": "...", "preview": true?}`。
有 `preview` 時只回傳計畫（`rule_ids`、`operations`、`by_kind`、`skipped`、`strict`）；否則回 202 與 `change_id`、
`direction`、`state`、`operations`、`skipped`、`strict`。對所有請求停用 CRS 規則（`"scope": {"mode": "all"}`）需要
專家模式規則，所以權杖會得到 403 `raw_admin_only`。

**`GET /changes`**：scope `changes:read`。`state` 是狀態名稱，或 `open`（所有尚未結束的狀態）；`limit`（預設 100，
最多 1000）；`cursor`。

**`GET /changes/{id}`**：scope `changes:read`。單一變更，含 `rule_text`、`checks`（靜態、證據、沙箱、差異）、`tests`、
`log`（誰在什麼時候做了什麼）、`error` 與 `applied_version`。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/changes/2
```
```json
{"id": 2, "op": "add", "kind": "confident_block", "rule_id": 10204, "direction": "tighten",
 "state": "pending_approval", "reason": "dotenv probes from outside", "proposed_by": "soar-playbook",
 "proposed_via": "api", "proposed_owner": "admin-a", "proposed_ip": "192.0.2.10",
 "created_at": "2026-11-13T15:13:48+08:00", "updated_at": "2026-11-13T15:13:49+08:00",
 "spec": {"target": "path", "regex": "^/\\.env$", "msg": "dotenv probe", "source": "external", "...": "..."},
 "summary": "path ~ ^/\\.env$", "error": null, "applied_version": null, "rule_text": "...",
 "checks": {"static": {"ok": true}, "evidence": {"ok": true, "complete": true, "external_hits": 41,
            "external_success": 0, "internal_other": 0, "...": "..."}, "sandbox": {"ok": true, "...": "..."},
            "diff": {"before": "..."}},
 "log": [{"ts": "2026-11-13T15:13:48+08:00", "actor": "soar-playbook", "action": "proposed", "note": "..."},
         {"ts": "2026-11-13T15:13:49+08:00", "actor": "system", "action": "checks_passed", "note": ""}]}
```

**`GET /versions`**：scope `changes:read`。已套用的規則檔版本，新的在前（`limit` 預設 50，最多 500）：`version`、
`created_at`、`change_id`、`kind`、`state`、`summary`、`step`、`health`、`nginx_t`。

**取消**變更不開放給權杖（403）。在網頁介面上由提出者或管理者取消；權杖提出的變更請找管理者。

### 4.5 規則、站台與 CRS

全部需要 scope `rules:read`。

- **`GET /rules`**：已載入的規則。`source` 是 `local`（預設）、`crs`、`plugin`、`vhost_inline`、`base` 或 `all`；
  另有 `category`、`family`、`state`（`on`、`off`、`partial`、`inactive`）、`q`（編號、訊息、註解或站台）、
  `limit`（預設 1000，最多 5000）、`cursor`。每筆有 `id`、`msg`、`source`、`state`、`provenance`、`hits_7d`、
  `hits_30d`、`last_hit` 等；回應另有 `total` 與 `summary`（各分類的數量）。
- **`GET /rules/{id}`**：單一規則，含規則文字與命中數。
- **`GET /rules/{id}/hits`**：每日命中數，`days` 1 到 365（預設 30）：
  `{"items": [{"day": "2026-11-12", "blocked": 3, "logged": 0}]}`。
- **`GET /rules/removals`**：被 `SecRuleRemoveById` 等指令移除的規則。
- **`GET /vhosts`**：nginx 站台與各自的 WAF 設定。
- **`GET /crs`**：CRS 版本、偏執等級、門檻、引擎模式、外掛。
- **`GET /crs/updates`**：jt-waf-mgr 是否負責更新 CRS、主機上有哪些版本、最新發行版。
- **`GET /waf/model`**：每個站台上一個請求如何被判定（引擎、計分、門檻、排除）。
- **`GET /managed`**：受管理規則檔與其中的項目（`items[].id` 就是變更用的 `item_id`）。
- **`GET /managed/items/{id}`**：單一受管理項目。
- **`GET /managed/files/{placement}`**：`placement` 是 `before` 或 `after`；以 `text/plain` 回傳檔案，加
  `?version=N` 則是某個已存版本。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" 'https://waf.example.com/api/v1/rules?source=local&state=on&limit=50'
```

### 4.6 IP 查詢

需要 scope `lookups:read`。

- **`GET /lookups/ip/{ip}`**：jt-waf-mgr 最近 7 天與 30 天從這個位址看到的事件。
- **`GET /geoip/{ip}`**：只回 GeoIP 結果（沒有安裝 GeoIP 資料庫時 `available: false`）。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/lookups/ip/198.51.100.23
```
```json
{"ip": "198.51.100.23", "origin": "external", "geo": {"scope": "external", "cc": "NL", "...": "..."},
 "d7": {"events": 12, "blocked": 9}, "d30": {"events": 40, "blocked": 31},
 "first_seen": "2026-10-20T03:11:09+08:00", "last_seen": "2026-11-13T15:13:27+08:00",
 "hosts": [{"key": "app.example.com", "events": 40}],
 "rules": [{"key": "941100", "events": 12, "msg": "XSS Attack Detected via libinjection", "family": "xss"}],
 "blocked_now": false, "blocks": []}
```

有暫時封鎖（4.9 節）涵蓋這個位址時，`blocked_now` 是 `true`，`blocks` 列出那些封鎖。

### 4.7 事件分析與回歸測試樣本

需要 scope `changes:read`。

- **`GET /analyst/status`**：排程事件分析（使用地端 LLM）是否啟用、是否就緒、設定值、下次與上次執行。
- **`GET /analyst/runs`**：過去的執行（`limit` 預設 50，最多 200；`cursor`）。
- **`GET /analyst/runs/{id}`**：單次執行，含候選、提案與警示。
- **`GET /regression`**：每次變更時沙箱會重送的請求清單。

### 4.8 稽核記錄

稽核記錄（`GET /audit`、`GET /audit/export`）只開放給以 session 登入的管理者，權杖會得到 403。要把稽核記錄送進
SIEM，請在網頁介面的設定中新增外送記錄目的地（syslog 等格式），並勾選稽核記錄。

### 4.9 暫時封鎖 IP

給看到攻擊者、想在一分鐘內把它封鎖在外的系統用，不經過變更與核准：例如網頁信箱在 WAF 後面的郵件主機，用 fail2ban
呼叫。封鎖是暫時的資料，不是設定，時間到就自動結束。

運作方式：jt-waf-mgr 把清單存在資料庫，由 root 的套用程式寫進一個 nginx 檔案（每行 `deny <位址>;`，最快每
`reload_seconds` 秒寫一次，預設 60），測試 nginx 後 reload。管理者在 `http { }` 裡加一次 include 這個檔案；jt-waf-mgr
本身不修改 nginx 設定。http 層的 `deny` 涵蓋所有站台（沒開 ModSecurity 的也算），但自己有 `allow` / `deny` 的 server
與 location 例外（「封鎖中的 IP」頁會列出）。在「設定」啟用之前，每個呼叫都回 409 `blocks_off`。

- **`POST /blocks`**（scope `blocks:write`）：內容 `{"ip", "ttl", "source", "reason"}`。
  - `ip`：單一位址（IPv4 或 IPv6）。網段只有人在網頁介面可以封鎖（最大 /24 或 /64）。
  - `ttl`：秒數，60 秒到 7 天（設定 `blocks.min_ttl`、`blocks.api_max_ttl`）；預設 24 小時。
  - `source`：呼叫的來源，`[A-Za-z0-9_.:@/+-]{1,64}`，例如 `mail2/zimbra-webmail`。
  - `reason`：必填，最多 300 字。
  - 同一個來源再送同一個位址，會延長到期時間（`extended` 加一），不會多一筆。不同來源各自一筆；最後一筆結束後才解除封鎖。
  - 回 201 與該筆資料：`{"id", "ip", "source", "reason", "state": "active", "created_at", "expires_at", "created_by",
    "via": "token", "extended", "ended_at", "ended_by"}`。
- **`DELETE /blocks/{ip}?source=`**（scope `blocks:write`）：解除這個權杖自己對該位址的封鎖（有 `source` 就只解除那個來源）。
  其他權杖的封鎖永遠不會動到：回 404 `not_found`。回 `{"removed": n}`。
- **`GET /blocks?state=active|all|removed|expired`**（scope `blocks:read`）：封鎖清單，以及 nginx 是否真的載入清單檔：
  `included`（在 `http { }` 裡載入時為 true）、`uncovered`（涵蓋不到的 server 與 location）、`applied`（最後寫入的時間與結果）、
  `in_sync`、`limits`。

會被拒絕（並寫進稽核 `block.refused`）的情況：

- 422 `not_public`（私有、迴環、鏈路本地、CGNAT、多播）、`protected`（內部網路、已知掃描器、信任的代理，或保護清單：
  例如站台前面的 CDN）、`invalid_ip`、`single_address_only`、`invalid_ttl`、`invalid_source`、`reason_required`；
- 429 `rate_limited`（同一個權杖一小時內新增超過 `blocks.token_per_hour`，預設 60）；
- 409 `too_many_blocks`（清單已滿，`blocks.max_active`，預設 500，會開立警示）或 `too_many_for_token`
  （`blocks.max_per_token`，預設 200）。

每次新增、延長、解除、拒絕、到期都寫進稽核記錄，並送到外送記錄目的地：`block.add`、`block.extend`、`block.remove`、
`block.refused`、`block.expired`，清單檔本身是 `block.applied` / `block.apply_failed`，帶 `ip`、`source`、`ttl`、`token_id`。

```sh
# fail2ban 的封鎖動作
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ip": "203.0.113.7", "ttl": 86400, "source": "mail2/zimbra-webmail", "reason": "4 failed logins in 24 h"}' \
  https://waf.example.com/api/v1/blocks
# fail2ban 的解除動作
curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" \
  'https://waf.example.com/api/v1/blocks/203.0.113.7?source=mail2/zimbra-webmail'
```

## 5. 只能在網頁介面使用的端點

下列端點對任何權杖都回 403。它們需要人、session，通常還要特定角色與當下的一次性密碼。

- 變更的決定：`POST /changes/{id}/approve`、`/reject`、`/cancel`、`/recheck`（證據覆核）、
  `POST /versions/{version}/rollback`、`POST /alerts/{id}/handle`。這些就是人工核准的步驟；如果權杖也能做，同一組機器
  憑證就能自己提出又自己通過變更。
- CRS：`POST /crs/updates/check`、`POST /crs/updates/propose`。
- 納管與上傳規則檔：`POST /managed/adopt`、`POST /managed/import/preview`、`POST /managed/import`。
- 帳號與權杖：`/auth/*`、`/users*`、`/tokens*`。
- 設定與維運：`/settings*`、`/workflow/settings`、`/notify/*`、`/llm/test`、`/geoip` 與 `/geoip/update`、
  `/backups*`、`/system/check`、`/compliance`、`/config-changes*`、`/analyst/run`、`POST /regression`、
  `DELETE /regression/{id}`、`POST /regression/collect`。
- 稽核：`/audit`、`/audit/export`、`/audit/verify`。

## 6. 變更流程

### 6.1 狀態

```
checking -> pending_approval -> approved -> applying -> applied
    |              |                            \-> apply_failed (rolled back automatically)
    \-> failed     \-> rejected                 applied -> rolled_back (a later version restored)
checking or pending_approval -> cancelled
```

- `checking`（檢查中）：背景正在檢查。如果期間有其他版本套用了，變更會回到這裡，針對新的檔案重新檢查。
- `failed`（檢查未通過）：有檢查沒過；看 `error` 與 `checks`。
- `pending_approval`（待核准）：全部檢查通過，等人核准。
- `approved`（已核准）：已核准並排隊（一次只套用一筆）。
- `applying`（套用中）：獨立的 root 程式寫入檔案、執行 `nginx -t`、reload、跑健康檢查。
- `applied`（已套用）：已生效；`applied_version` 是版本號。
- `apply_failed`（套用失敗）：套用過程失敗，已自動還原成原本的檔案。
- `rejected`（已退回）、`cancelled`（已取消）、`rolled_back`（已還原）：結束。

結束狀態是 `applied`、`rejected`、`cancelled`、`failed`、`apply_failed`、`rolled_back`。

### 6.2 檢查

- **靜態**：規則能從範本產生；產生後檔案中的每條規則都通過專家模式檢查（不可關閉引擎、不可用讀檔運算子、不可改稽核
  記錄設定等）；規則編號沒有重複。
- **證據**：確定阻擋會掃描存取記錄中正規表示式比對到的請求。如果某個會被封鎖的外部請求在一般站台上得到 2xx/3xx 回應、
  某個內部位址（已知掃描器除外）會被封鎖，或掃描沒有在時限內完成，檢查就不通過。排除則以最近 30 天的事件呈現它會影響
  哪些請求。證據檢查沒過時，只能由人寫下理由後覆核（在網頁介面重新檢查）。
- **沙箱**：用正式設定加上這筆變更的拋棄式 nginx，重送變更的 `tests` 與回歸測試樣本。主機沒有沙箱時，只有管理者把沙箱
  設為非必要，這項檢查才算通過。

### 6.3 核准

- 由核准者或管理者在網頁介面（`/changes/<id>`）核准。放寬一定要經過這一步。
- 用權杖提出的變更歸屬於建立該權杖的管理者：這位管理者不能核准，除非開啟了「單人模式」（此時放寬類要當下的一次性
  密碼與書面理由）。
- 收緊類自動套用**預設關閉**。管理者開啟後，`add` 一筆 `source: external` 的 `confident_block`，且證據顯示沒有成功的
  外部請求、也沒有內部請求時，可能不經人核准就套用（每天有上限）。所以腳本在等待時也要接受 `approved`、`applying`、
  `applied`。

## 7. 實例：從腳本提出一筆確定阻擋

這個腳本為 `/.env` 探測提出封鎖規則，等檢查完成，然後印出給核准者的連結。需要 `curl`、`jq`，以及一個有
`changes:propose` 與 `changes:read`、並限定腳本所在主機為來源的權杖。

```sh
#!/bin/sh
set -eu
BASE='https://waf.example.com/api/v1'
TOKEN='jwm_example00000_EXAMPLE-not-a-real-token'

# 1. 先驗證 spec（不會建立任何東西）
SPEC='{"target": "path", "regex": "^/\\.env$", "msg": "dotenv probe", "source": "external"}'
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"kind\": \"confident_block\", \"spec\": $SPEC}" "$BASE/changes/preview" | jq -e '.ok' >/dev/null

# 2. 提出變更
CID=$(curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{
  \"kind\": \"confident_block\", \"spec\": $SPEC,
  \"reason\": \"SIEM case 4711: /.env probes from 203.0.113.0/24\",
  \"tests\": [{\"host\": \"app.example.com\", \"path\": \"/.env\", \"source\": \"external\", \"expect\": 403},
             {\"host\": \"app.example.com\", \"path\": \"/\", \"source\": \"external\", \"expect\": 200}]
}" "$BASE/changes" | jq -er '.change_id')
echo "change $CID proposed"

# 3. 每 10 秒查一次，最多 10 分鐘
i=0
while [ $i -lt 60 ]; do
  STATE=$(curl -sS -H "Authorization: Bearer $TOKEN" "$BASE/changes/$CID" | jq -r '.state')
  case "$STATE" in
    checking) sleep 10; i=$((i + 1)) ;;
    pending_approval) echo "checks passed; approve at https://waf.example.com/changes/$CID"; exit 0 ;;
    approved|applying|applied) echo "applied automatically (state $STATE)"; exit 0 ;;
    *) curl -sS -H "Authorization: Bearer $TOKEN" "$BASE/changes/$CID" | jq '{state, error, checks}'; exit 1 ;;
  esac
done
echo "still checking after 10 minutes"; exit 1
```

接著由人登入網頁介面，打開**變更**（或上面的連結），看過檢查結果與差異後核准或退回。腳本可以繼續輪詢
`GET /changes/{id}` 直到結束狀態，或等 `applied` 與 `applied_version` 出現。
