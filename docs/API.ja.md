# API 連携マニュアル

[English](API.md) · [繁體中文](API.zh-TW.md) · **日本語**

このマニュアルは、他のシステムを jt-waf-mgr につなぐ人のためのものです。SIEM で WAF のイベントを取り込む、SOAR の
プレイブックからブロックを提案する、スクリプトから呼び出す、といった用途を想定しています。Web 画面も同じエンドポイントを
サインイン済みのセッションで呼び出していますが、連携するシステムは **API トークン**を使います。以下はトークンでできる
ことの説明です。

> **API トークンは変更を提案できますが、承認は決してできません。** 承認、却下、取り消し、ロールバックは人が Web 画面で
> 行います。トークンからの提案も、他の提案と同じすべてのチェックを通ります。

例はすべて架空の値です：`waf.example.com`、192.0.2.0/24・198.51.100.0/24・203.0.113.0/24 のアドレス、偽のトークン。

## 1. 基本

- **ベース URL**：`https://<jt-waf-mgr のホスト>/api/v1`。例：`https://waf.example.com/api/v1`。jt-waf-mgr は
  127.0.0.1 で待ち受け、その前に nginx があります。その nginx のサイト経由で呼び出してください。
- **JSON**：応答は UTF-8 の JSON（`application/json; charset=utf-8`）です（NDJSON エクスポートとルールファイルの
  ダウンロードを除く）。本文のあるリクエストは `Content-Type: application/json` と JSON オブジェクトを送る必要があり、
  そうでなければ 415 か 400 になります。本文の上限はデフォルトで 1 MiB です（超えると 413 `payload_too_large`）。
- **バージョン**：メジャーバージョンはパスにあります（`/api/v1`）。`GET /meta` がプログラムのバージョンを返します。
  フィールドは今後も追加されるので、知らないフィールドは無視してください。
- **時刻**：応答は RFC 3339、サーバーのローカルなオフセット付き、秒単位です。例：`2026-11-13T15:13:27+08:00`。
  `since`・`until` などのパラメーターは RFC 3339（`Z` またはオフセット）を受け付けます。オフセットのない時刻や日付だけの
  場合は、サーバーのローカル時刻として解釈します。
- **ページング**：一覧は `limit` と `cursor` を受け付け、`next_cursor`（文字列、最後のページでは `null`）を返します。
  `next_cursor` をそのまま `cursor` に渡してください。特に記載がなければ新しい順です。
- **キャッシュと圧縮**：API の応答にはすべて `Cache-Control: no-store` が付きます。`Accept-Encoding: gzip` を送ると
  大きな応答は圧縮されます。
- **機密データ**：リクエストデータ中のパスワードなどの項目は、保存前にマスクされます。原文を見るオプションはありません。

## 2. 認証

### 2.1 トークンの作成

- トークンを作成できるのは**管理者**だけです。Web 画面の**管理 > API トークン**（`/admin/tokens`）の
  「トークンを作成」で行います。
- 名前（呼び出し元のシステム名など）、許可する送信元アドレス、有効期限（任意）、1 つ以上のスコープを指定します。
- トークンは作成直後に**一度だけ**表示されます。呼び出し元のシークレット保管庫にすぐコピーしてください。データベースには
  ハッシュだけが保存されるため、なくしたトークンは再表示できません。失効させて作り直してください。
- 形式は `jwm_<12 文字>_<シークレット>` です。例では偽のトークン
  `jwm_example00000_EXAMPLE-not-a-real-token` を使います。
- 同じページでトークンの一覧（スコープ、送信元、有効期限、最終使用）を確認し、失効させられます。失効は即時に効きます。
- トークンで提案された変更は、そのトークンを作成した管理者のものになります。その管理者はそれらの変更を承認できません
  （6.3 参照）。

### 2.2 スコープ

トークンには次のスコープを 1 つ以上付けます。これ以外はありません。

- `status:read`：`GET /status`。
- `events:read`：イベント、イベント統計、タイムライン、概要、NDJSON エクスポート。
- `rules:read`：ルール、ルールのヒット、サイト（vhost）、CRS の状態と更新、WAF の判定モデル、管理対象ルールファイル。
- `lookups:read`：IP 検索と GeoIP 検索。
- `changes:read`：変更、バージョン、アラート、イベント分析の実行記録、回帰テストのサンプル。
- `changes:propose`：変更の提案（`POST /changes`、`POST /changes/preview`、`POST /rules/toggle`）。承認は不可。
- `blocks:read`：一時的な IP ブロックの一覧（`GET /blocks`）。
- `blocks:write`：そのトークン自身の一時的な IP ブロックの追加・延長・解除（単一アドレスのみ）。

トークンには必要なスコープだけを付けてください。イベントを読むだけの SIEM なら `events:read`、ブロックを提案する
プレイブックなら `changes:propose` と `changes:read` です。

### 2.3 送信元の制限

- 「許可する送信元アドレス」は CIDR のリストです（例：`192.0.2.10/32, 198.51.100.0/24`）。空欄なら送信元を問いません。
  制限することを強く推奨します。
- 照合するのは jt-waf-mgr から見た送信元アドレス、つまりローカルの nginx が設定する `X-Real-IP` です（信頼済みの
  プロキシからのものだけを受け付けます）。呼び出し元が、送信元を隠す別のプロキシを経由せずにこの nginx へ直接つながる
  ようにしてください。
- 他のアドレスからの呼び出しは 403 `token_source_not_allowed` になり、監査記録に残ります。

### 2.4 有効期限

- 任意です。有効期限がなければ、失効させるまで有効です。
- 期限切れ、失効済み、存在しない、形式が誤っているトークンはすべて 401 `invalid_token` になります。

### 2.5 トークンの送り方

`Authorization` ヘッダーで `Bearer` 方式で送ります。トークンには Cookie も CSRF ヘッダーも不要です。

```sh
TOKEN='jwm_example00000_EXAMPLE-not-a-real-token'
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/status
```

トークンでの呼び出しはすべて監査記録に残ります（`token.used`、拒否されたときは理由付きの `token.denied`）。トークン名、
送信元アドレス、エンドポイントが記録されます。

### 2.6 セッション（参考）

Web 画面はユーザー名、パスワード、ワンタイムコードでサインインしてセッション Cookie を受け取り、状態を変えるリクエスト
ごとに `X-CSRF-Token` を送ります。連携ではセッションを使わず、トークンを使ってください。

## 3. エラーと制限

エラーはすべて同じ形です：

```json
{"error": {"code": "token_source_not_allowed", "message": "token source not allowed", "details": {}}}
```

プログラムでは `code` で判断してください。`message` は人向け、`details` は補足（どの項目が不正かなど）です。主なコード：

- **400**：`bad_request`（パラメーターの形式が不正。例：`limit must be a number`）、`reason_required`、`invalid_op`、
  `invalid_kind`、`invalid_tests`、`no_effect`（すでに無効な項目を無効にする、など）。
- **401**：`not_authenticated`（トークンを送っていない）、`invalid_token`（存在しない、形式不正、失効済み、期限切れ）。
- **403**：メッセージ `token lacks scope` の `forbidden`（`details.scope` が必要なスコープ。どのトークンも呼べない
  エンドポイントでは `null`）、メッセージ `not available to API tokens` の `forbidden`（管理とアカウントの
  エンドポイント）、`token_source_not_allowed`、`raw_admin_only`（エキスパートルール、4.4 参照）。
- **404**：`not_found`、`item_not_found`（`item_id` の管理対象項目が存在しない）。
- **405**：`method_not_allowed`。
- **409**：`not_adopted`（jt-waf-mgr がまだサイトのルールファイルを管理下に置いていないため、変更を提案できない）、
  `invalid_state`（`details.state`）、`rule_id_in_use`、`id_range_full`、`nothing_to_change`。
- **413** `payload_too_large`、**415**（コードは `bad_request`）：本文が `application/json` ではない。
- **422**：`invalid_spec`（`details.field` と `details.reason`。例：`regex` と `too_broad`）、`invalid_bundle`
  （`details.index`、`details.limit` または `details.reason`）、`invalid_rule_ids`、`invalid_group`、`invalid_scope`、
  `scope_required`、`invalid_action`。
- **429** `too_many_attempts`（`Retry-After` ヘッダー付き）：サインインやワンタイムコードの試行が多すぎる。指定された
  秒数だけ待ってください。
- **500** `internal_error`。

**レート制限**：このバージョンにはトークンごとのリクエストレート制限はありません。ポーリングは控えめな間隔で行い
（下の例では 10 秒ごと）、429 を受け取ったら `Retry-After` に従ってください。jt-waf-mgr の前段のリバースプロキシが独自の
制限をかけている場合があります。

## 4. エンドポイント

以下のパスは `/api/v1` からの相対パスです。「スコープ」はトークンに必要なスコープです。

### 4.1 メタ情報と状態

**`GET /meta`**：認証不要。名前、バージョン、ソースコードの URL、ノード ID。

```sh
curl -sS https://waf.example.com/api/v1/meta
```
```json
{"name": "jt-waf-mgr", "version": "0.4.22", "source_url": "https://...",
 "sso_enabled": false, "node_id": "waf1", "login_notice": "", "password_policy": {"min_length": 12, "...": "..."}}
```

**`GET /status`**：スコープ `status:read`。エンジンモード、CRS の設定、ModSecurity の監査記録を読む収集処理の状態
（監視には `collector.running`、`lag_seconds`、`last_event_at` を使います）。

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

### 4.2 イベント

**`GET /events`**：スコープ `events:read`。イベントの一覧、新しい順。パラメーター（すべて任意）：

- `since`、`until`：RFC 3339。
- `host`（完全一致）、`path_prefix`、`q`（パスに含まれる文字列）。
- `src_ip`：アドレス、または `203.0.113.0/24` のようなネットワーク。
- `country`：2 文字の国コード。外部の送信元のみ、GeoIP が必要。
- `rule_id`：このルールがマッチしたイベント。
- `outcome`：`blocked` または `logged`。`origin`：`external` または `internal`。
- `decided_by`：`confident`、`score`、`fallback`、`other`。
- `family`：`protocol`、`lfi`、`rfi`、`rce`、`php`、`generic`、`xss`、`sqli`、`session`、`java`、`scanner`、
  `method`、`body`、`data_leak`、`local`、`other`。
- `limit`（デフォルト 100、最大 1000）、`cursor`。

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

**`GET /events/{id}`**：スコープ `events:read`。1 件のイベント。ルールのマッチ内容、異常スコア、接続情報を含みます。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/events/1
```
```json
{"id": 1, "...": "一覧の項目に加えて：", "unique_id": "...", "http_version": "1.1",
 "engine": "Enabled", "client_port": 51234, "server_port": 443, "anomaly_score": null,
 "matches": [{"rule_id": 10205, "message": "...", "severity": "CRITICAL", "data": "", "match": "...",
              "tags": [], "file": "...", "line": 50, "family": "local", "local": true}],
 "truncated": false}
```

**`GET /events/export`**：スコープ `events:read`。SIEM 向けの差分エクスポート。NDJSON（1 行に完全なイベント 1 件）で、
**古い順**です。`cursor` は手元にある最後のイベント ID（最初は 0）、`limit` はデフォルト 1000、最大 5000。応答ヘッダーの
`X-Next-Cursor`（次回のために保存）と `X-Content-SHA256`（本文の SHA-256）を使います。本文が空なら最新に追いついています。
このエンドポイントにはフィルターは効きません。

```sh
curl -sS -D headers.txt -H "Authorization: Bearer $TOKEN" \
  'https://waf.example.com/api/v1/events/export?cursor=0&limit=1000' > events.ndjson
grep -i '^x-next-cursor' headers.txt
```

**`GET /events/stats`**：スコープ `events:read`。`group_by` ごとの件数：`host`（デフォルト）、`rule`、`src_ip`、
`family`、`hour`。範囲は `since` から `until`（デフォルトは直近 24 時間）。

```json
{"group_by": "rule", "items": [{"key": "10205", "msg": "...", "family": "local", "blocked": 1, "logged": 0}]}
```

**`GET /events/timeline`**：スコープ `events:read`。フィルターは `/events` と同じ。`since`・`until` のデフォルトは直近
7 日、最大 31 日（短縮されたときは `clamped: true`）。7 日以内は 1 時間ごと、それを超えると 1 日ごとです。

**`GET /overview`**：スコープ `events:read`。概要ページの数値。`range` は `24h`（デフォルト）、`7d`、または `since` と
`until` を付けた `custom`（1 時間から 31 日）で、イベントのフィルターも使えます。`totals`、`previous`（直前の同じ長さの
期間）、`timeline`、`by_host`、`by_family`、`by_src`、`by_rule`、`by_country`、`by_asn` などを返します。

### 4.3 アラート

アラートは人が確認すべき事柄です（通過した可能性のある攻撃、誤検知の疑い、完全性の問題、適用の失敗など）。

- **`GET /alerts`**：スコープ `changes:read`。`state` は `open` または `handled`、`limit`（デフォルト 50、最大 200）、
  `cursor`。応答には `counts` が付きます。
- **`GET /alerts/counts`**：スコープ `changes:read`。`{"open": 3, "critical": 1}`。
- **`GET /alerts/{id}`**：スコープ `changes:read`。

`kind` は `attack_in_progress`、`attack_passed`、`false_positive`、`integrity`、`config_outside`、`apply_failed`、
`backup_failed`、`auth_attack`、`crs_update`、`other` のいずれか、`severity` は `critical` または `warning` です。

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

アラートを対応済みにするのは、承認者が Web 画面で行います。

### 4.4 変更

変更とは、jt-waf-mgr の管理対象ルールファイルでルールを 1 つ追加・修正・無効化・有効化・削除する提案、またはそれを
まとめて行う提案（一括）です。提案するには、jt-waf-mgr がすでにサイトのルールファイルを管理下に置いている必要があります
（管理者が一度だけ行います）。それまではすべての提案が 409 `not_adopted` になります。

**`POST /changes/preview`**：スコープ `changes:propose`。何も作成せず、ルールを生成して返します。提案の前に `spec` を
検証するのに使います。検証エラーは 200 と `ok: false` で返ります。

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

**`POST /changes`**：スコープ `changes:propose`。本文：

- `op`：`add`（デフォルト）、`modify`、`disable`、`enable`、`delete`、`bundle`。
- `kind`：`add` のとき `confident_block`、`exclusion`、`country`、`redaction`、`plugin`、`raw`。
- `spec`：種類ごとの項目（下記）。`modify` では新しい spec をすべて渡します。
- `item_id`：`modify`、`disable`、`enable`、`delete` のとき、管理対象項目の ID（`GET /managed` の `items[].id`）。
- `reason`：必須、2000 文字まで。承認者に表示されます。
- `tests`：任意。サンドボックスで実際に送るリクエスト（最大 50 件）：`{"host", "path", "expect": 200 | 403,
  "source": "external" | "internal", "method"?, "headers"?, "body"?}`。

応答は 202 と変更 ID です。チェックはバックグラウンドで行われます：

```json
{"change_id": 2, "direction": "tighten", "state": "checking", "rule_id": 10204}
```

`direction` は `tighten`（強化：ブロックや検査が増える）または `loosen`（緩和：減る）です。判断できないものはすべて
緩和として扱います。緩和には必ず人の承認が必要です。

**種類 `confident_block`**（確定ブロック：確実に攻撃であるリクエストを、異常スコアに関係なくブロック）：

- `target`：`path`（デフォルト。URL デコード、正規化、小文字化）、`uri`（パスとクエリ、小文字化）、`ua`
  （User-Agent）、`host`、または `header`（このとき `header` で名前を指定。例：`X-Api-Version`）。
- `regex`：必須、1000 文字まで、ダブルクォートと改行は不可。空文字列にマッチする（`matches_empty`）、ほぼすべての通常の
  リクエストにマッチする（`too_broad`）、破滅的なバックトラックのおそれがある（`redos_shape`、`redos_runtime`）場合は
  拒否されます。
- `msg`：必須、100 文字まで、引用符とバックスラッシュは不可。ルールのメッセージは `jt confident block: <msg>` に
  なります。
- `exceptions`：任意。決してブロックしないパスの正規表現（最大 10 個）。
- `host`：任意。`{"mode": "any"}`（デフォルト）、`{"mode": "exact", "value": "app.example.com"}`
  （`*.example.com` も可）、または `{"mode": "regex", "value": "..."}`。
- `reference`：任意、200 文字まで（チケットやアドバイザリの番号）。
- `source`：`external`（デフォルト。内部アドレスは決してブロックしない）または `all`（内部アドレスもブロック。ただし
  既知のスキャナーは除く）。

**種類 `exclusion`**（除外：誤検知を起こす場所でルールを発動させない。常に緩和）：

- `host` と `path` の少なくとも一方：`path` は `{"mode": "exact" | "prefix" | "regex", "value": "/search"}`。
- `method`：任意。例：`POST`。`source`：`all`（デフォルト）、`external`、`internal`。
- `action`：`remove_target_by_id`（デフォルト。`rule_ids` と `targets` が必要）、`remove_target_by_tag`（`tag` と
  `targets`）、`remove_rule`（`rule_ids`）、`remove_tag`（`tag` と `confirm_tag: true`）、`score_only`、または
  `body_processor`（`body_processor` は `JSON`、`XML`、`URLENCODED`、`MULTIPART`）。
- `rule_ids`：最大 20 個。`targets`：`ARGS:q`、`REQUEST_COOKIES:session` のような ModSecurity 変数、最大 20 個。

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

**種類 `country`**（0.4.27 で追加。国で 1 つのサイトを制限。設定で国別ブロックをオンにし、一覧をダウンロード済みで
あること。そうでなければ 409 `countries_off` / `countries_no_data`）：

- `host`：必須、`{"mode": "exact", "value": "shop.example.com"}`（`*.example.com` も可）。
- `mode`：`allow`（これらの国のみ許可）または `deny`（これらの国をブロック）。
- `countries`：一覧のある ISO 3166 の 2 文字国コードを 1〜50 個（なければ 422 `unknown_country`）。
- `note`：任意、160 文字まで。

内部ネットワーク、既知のスキャナー、信頼するプロキシ、保護リストは決してブロックしません。テストが 3 つ自動で追加されます
（許可される国、ブロックされる国、内部から各 1 つ）。`tests` には `src_ip`（`external` のみ）で公開の送信元アドレスも指定できます。
証拠チェックはアクセスログからこのルールがブロックしたはずの量（`requests`、`refused`、`refused_sources`、`refused_success`、
`countries`）を数えます。参考情報であり、変更を失敗させることはありません。国別ブロックは自動では適用されません。
`GET /countries`（ログイン中の利用者。トークンのスコープはなし）で、一覧のある国と使用中の一覧を返します。

**種類 `redaction` と `plugin`**：`redaction` は `fields`（検査しない引数名、最大 30 個。検査しないので監査記録にも
コピーされません）と任意の `host`・`path`、`plugin` は `plugin`（CRS プラグイン名）と必須の `host` で、1 つのサイトで
プラグインを有効にします。

**種類 `raw`**（エキスパートモード：書いたとおりの SecRule）：エキスパートルールの追加と修正は**管理者が Web 画面で
行う場合に限られます**。トークンは 403 `raw_admin_only` になります（既存のエキスパート項目の無効化・有効化・削除は
トークンでも可能です）。

**一括**（`"op": "bundle"`）：複数の操作を 1 件の変更にまとめ、一緒にチェック・承認・適用します（1 つのバージョン、
1 回の reload、1 回のロールバック）。`ops` には `{"op", "kind", "spec", "item_id"}` を 1〜100 個、うち確定ブロックは
最大 20 個まで入れられます。すべての操作が強化のときだけ、一括全体が強化になります。

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

**`POST /rules/toggle`**：スコープ `changes:propose`。複数のルール、またはカテゴリ全体を 1 件の変更として無効化・有効化
します：`{"action": "disable" | "enable", "rule_ids": [...]（最大 300 個）または "group": {"source": "crs" | "local",
"key": "<攻撃ファミリーまたはカテゴリ>"}, "scope": {"mode": "hosts", "hosts": ["app.example.com"]}, "reason": "...",
"preview": true?}`。`preview` を付けると計画だけを返します（`rule_ids`、`operations`、`by_kind`、`skipped`、`strict`）。
付けなければ 202 と `change_id`、`direction`、`state`、`operations`、`skipped`、`strict` を返します。すべての
リクエストで CRS ルールを無効にする（`"scope": {"mode": "all"}`）にはエキスパートルールが必要なため、トークンは 403
`raw_admin_only` になります。

**`GET /changes`**：スコープ `changes:read`。`state` は状態名、または `open`（終了していないすべての状態）、`limit`
（デフォルト 100、最大 1000）、`cursor`。

**`GET /changes/{id}`**：スコープ `changes:read`。1 件の変更。`rule_text`、`checks`（静的、根拠、サンドボックス、差分）、
`tests`、`log`（誰がいつ何をしたか）、`error`、`applied_version` を含みます。

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

**`GET /versions`**：スコープ `changes:read`。適用されたルールファイルのバージョン、新しい順（`limit` デフォルト 50、
最大 500）：`version`、`created_at`、`change_id`、`kind`、`state`、`summary`、`step`、`health`、`nginx_t`。

変更の**取り消し**はトークンではできません（403）。Web 画面で提案者か管理者が取り消します。トークンで提案した変更は
管理者に依頼してください。

### 4.5 ルール、サイト、CRS

すべてスコープ `rules:read` です。

- **`GET /rules`**：読み込まれているルール。`source` は `local`（デフォルト）、`crs`、`plugin`、`vhost_inline`、
  `base`、`all`。ほかに `category`、`family`、`state`（`on`、`off`、`partial`、`inactive`）、`q`（ID、メッセージ、
  コメント、ホスト）、`limit`（デフォルト 1000、最大 5000）、`cursor`。各項目には `id`、`msg`、`source`、`state`、
  `provenance`、`hits_7d`、`hits_30d`、`last_hit` などがあり、応答には `total` と `summary`（カテゴリごとの件数）も
  含まれます。
- **`GET /rules/{id}`**：1 つのルール。ルールの本文とヒット数を含みます。
- **`GET /rules/{id}/hits`**：日ごとのヒット数。`days` は 1〜365（デフォルト 30）：
  `{"items": [{"day": "2026-11-12", "blocked": 3, "logged": 0}]}`。
- **`GET /rules/removals`**：`SecRuleRemoveById` などで除去されたルール。
- **`GET /vhosts`**：nginx のサイトとその WAF 設定。
- **`GET /crs`**：CRS のバージョン、パラノイアレベル、しきい値、エンジンモード、プラグイン。
- **`GET /crs/updates`**：jt-waf-mgr が CRS を更新しているか、ホスト上のバージョン、最新のリリース。
- **`GET /waf/model`**：各サイトでリクエストがどう判定されるか（エンジン、スコア、しきい値、除外）。
- **`GET /managed`**：管理対象ルールファイルとその項目（`items[].id` が変更で使う `item_id`）。
- **`GET /managed/items/{id}`**：1 つの管理対象項目。
- **`GET /managed/files/{placement}`**：`placement` は `before` または `after`。ファイルを `text/plain` で返します。
  `?version=N` を付けると保存済みのバージョンです。

```sh
curl -sS -H "Authorization: Bearer $TOKEN" 'https://waf.example.com/api/v1/rules?source=local&state=on&limit=50'
```

### 4.6 IP 検索

スコープ `lookups:read` が必要です。

- **`GET /lookups/ip/{ip}`**：jt-waf-mgr がそのアドレスについて直近 7 日と 30 日に見たもの。
- **`GET /geoip/{ip}`**：GeoIP の結果だけ（GeoIP データベースがないときは `available: false`）。

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

一時的な IP ブロック（4.9 節）がそのアドレスを含むとき、`blocked_now` は `true` になり、`blocks` にその一覧が入ります。

### 4.7 イベント分析と回帰テストのサンプル

スコープ `changes:read` が必要です。

- **`GET /analyst/status`**：定期イベント分析（ローカル LLM を使用）が有効か、準備ができているか、設定、次回と前回の実行。
- **`GET /analyst/runs`**：過去の実行（`limit` デフォルト 50、最大 200、`cursor`）。
- **`GET /analyst/runs/{id}`**：1 回の実行。候補、提案、アラートを含みます。
- **`GET /regression`**：変更のたびにサンドボックスが再送するリクエストの一覧。

### 4.8 監査記録

監査記録（`GET /audit`、`GET /audit/export`）はセッションでサインインした管理者専用で、トークンは 403 になります。監査
記録を SIEM に送るには、Web 画面の設定で外部送信先（syslog などの形式）を追加し、監査記録を含めてください。

### 4.9 一時的な IP ブロック

攻撃者を見つけ、変更と承認を経ずに 1 分以内に締め出したいシステム向けです。たとえば Web メールが WAF の後ろにある
メールサーバーの fail2ban から呼び出します。ブロックは設定ではなく一時的なデータで、期限が来ると自動で終わります。

仕組み：jt-waf-mgr は一覧をデータベースに保存し、root の適用プログラムが 1 つの nginx ファイル（`deny <アドレス>;` の行。
最短で `reload_seconds` 秒ごと、既定 60）に書き込み、nginx をテストして reload します。管理者は `http { }` の中で
このファイルを一度だけ include します。jt-waf-mgr 自身は nginx の設定を変更しません。http レベルの `deny` は
ModSecurity を使わないサイトも含めてすべてのサイトに効きますが、独自の `allow` / `deny` を持つ server と location は
例外です（「ブロック中の IP」ページに表示）。ブロックは reload 以降の新しいリクエストと接続に効きます。ブロック前から開いている接続（WebSocket、長時間のダウンロード）は切断されず、自然に閉じるまで続きます。設定でオンにするまで、すべての呼び出しは 409 `blocks_off` を返します。

- **`POST /blocks`**（スコープ `blocks:write`）：本文 `{"ip", "ttl", "source", "reason"}`。
  - `ip`：単一アドレス（IPv4 または IPv6）。範囲のブロックは Web 画面の人だけ（/24 または /64 まで）。
  - `ttl`：秒数、60 秒から 7 日（設定 `blocks.min_ttl`、`blocks.api_max_ttl`）。既定は 24 時間。
  - `source`：呼び出し元、`[A-Za-z0-9_.:@/+-]{1,64}`。例：`mail2/zimbra-webmail`。
  - `reason`：必須、300 文字まで。
  - 同じ送信元が同じアドレスを再送すると期限を延長し（`extended` が増える）、2 件目は作りません。送信元が違えば
    それぞれ 1 件になり、最後の 1 件が終わるまでブロックは続きます。
  - 201 とその内容を返します：`{"id", "ip", "source", "reason", "state": "active", "created_at", "expires_at",
    "created_by", "via": "token", "extended", "ended_at", "ended_by"}`。
- **`DELETE /blocks/{ip}?source=`**（スコープ `blocks:write`）：そのトークン自身のそのアドレスのブロックを解除します
  （`source` を付けるとその送信元だけ）。他のトークンのブロックには触れません（404 `not_found`）。`{"removed": n}` を返します。
- **`GET /blocks?state=active|all|removed|expired`**（スコープ `blocks:read`）：一覧と、nginx が本当にファイルを読み込んで
  いるか：`included`（`http { }` の中で読み込まれていれば true）、`uncovered`（効かない server と location）、`applied`
  （最後に書き込んだ時刻と結果）、`in_sync`、`limits`。

拒否される場合（拒否は監査ログ `block.refused` に記録）：

- 422 `not_public`（プライベート、ループバック、リンクローカル、CGNAT、マルチキャスト）、`protected`（内部ネットワーク、
  既知のスキャナー、信頼するプロキシ、保護リスト：たとえばサイトの前の CDN）、`invalid_ip`、`single_address_only`、
  `invalid_ttl`、`invalid_source`、`reason_required`。
- 429 `rate_limited`（1 つのトークンが 1 時間に `blocks.token_per_hour` を超えて追加、既定 60）。
- 409 `too_many_blocks`（一覧が満杯、`blocks.max_active`、既定 500。警告を作成）または `too_many_for_token`
  （`blocks.max_per_token`、既定 200）。

追加、延長、解除、拒否、期限切れはすべて監査ログに記録され、ログ転送先にも送られます：`block.add`、`block.extend`、
`block.remove`、`block.refused`、`block.expired`。リストファイル自体は `block.applied` / `block.apply_failed`。
`ip`、`source`、`ttl`、`token_id` が付きます。

```sh
# fail2ban のブロック
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ip": "203.0.113.7", "ttl": 86400, "source": "mail2/zimbra-webmail", "reason": "4 failed logins in 24 h"}' \
  https://waf.example.com/api/v1/blocks
# fail2ban の解除
curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" \
  'https://waf.example.com/api/v1/blocks/203.0.113.7?source=mail2/zimbra-webmail'
```

## 5. Web 画面専用のエンドポイント

次のエンドポイントはどのトークンにも 403 を返します。人とセッション、多くの場合は特定のロールとその場のワンタイムコードが
必要です。

- 変更の決定：`POST /changes/{id}/approve`、`/reject`、`/cancel`、`/recheck`（根拠の上書き）、
  `POST /versions/{version}/rollback`、`POST /alerts/{id}/handle`。これが人による承認の手順です。トークンでもできると、
  1 つの機械用の資格情報で変更を提案し、そのまま通せてしまいます。
- CRS：`POST /crs/updates/check`、`POST /crs/updates/propose`。
- 管理下への取り込みとルールファイルのアップロード：`POST /managed/adopt`、`POST /managed/import/preview`、
  `POST /managed/import`。
- アカウントとトークン：`/auth/*`、`/users*`、`/tokens*`。
- 設定と運用：`/settings*`、`/workflow/settings`、`/notify/*`、`/llm/test`、`/geoip` と `/geoip/update`、`/backups*`、
  `/system/check`、`/compliance`、`/config-changes*`、`/analyst/run`、`POST /regression`、`DELETE /regression/{id}`、
  `POST /regression/collect`。
- 監査：`/audit`、`/audit/export`、`/audit/verify`。

## 6. 変更の流れ

### 6.1 状態

```
checking -> pending_approval -> approved -> applying -> applied
    |              |                            \-> apply_failed (rolled back automatically)
    \-> failed     \-> rejected                 applied -> rolled_back (a later version restored)
checking or pending_approval -> cancelled
```

- `checking`（チェック中）：バックグラウンドでチェック中。その間に別のバージョンが適用されると、新しいファイルに対して
  チェックし直すためここに戻ります。
- `failed`（チェック失敗）：通らなかったチェックがあります。`error` と `checks` を見てください。
- `pending_approval`（承認待ち）：すべてのチェックに通過し、人の承認を待っています。
- `approved`（承認済み）：承認され、順番待ち（適用は一度に 1 件）。
- `applying`（適用中）：独立した root のプログラムがファイルを書き、`nginx -t`、reload、ヘルスチェックを行っています。
- `applied`（適用済み）：反映済み。`applied_version` がバージョン番号です。
- `apply_failed`（適用失敗）：適用中に失敗し、元のファイルに自動で戻しました。
- `rejected`（却下）、`cancelled`（取り消し）、`rolled_back`（ロールバック済み）：終了。

終了状態は `applied`、`rejected`、`cancelled`、`failed`、`apply_failed`、`rolled_back` です。

### 6.2 チェック

- **静的**：ルールがテンプレートから生成できること。生成後のファイルのすべてのルールがエキスパートモードのチェックに通る
  こと（エンジンの停止、ファイルを読む演算子、監査記録の設定変更などは不可）。ルール ID が重複しないこと。
- **根拠**：確定ブロックでは、正規表現にマッチするリクエストをアクセス記録から探します。ブロック対象になる外部の
  リクエストが通常のサイトで 2xx/3xx を返していた場合、内部アドレス（既知のスキャナーを除く）がブロックされる場合、
  または時間内に走査が終わらなかった場合は不合格です。除外では、直近 30 日のイベントからどのリクエストに影響するかを
  示します。根拠チェックの不合格を上書きできるのは、理由を書いた人だけです（Web 画面での再チェック）。
- **サンドボックス**：本番の設定にこの変更を加えた使い捨ての nginx で、変更の `tests` と回帰テストのサンプルを再送します。
  ホストにサンドボックスがない場合は、管理者がサンドボックスを必須でない設定にしているときだけ合格になります。

### 6.3 承認

- 承認者または管理者が Web 画面（`/changes/<id>`）で承認します。緩和は必ずこの手順を通ります。
- トークンで提案された変更は、そのトークンを作成した管理者のものです。その管理者は承認できません。ただし「単独管理者
  モード」が有効なら承認でき、緩和の場合はその場のワンタイムコードと理由の記入が必要です。
- 強化の自動適用は**デフォルトで無効**です。管理者が有効にすると、`source: external` の `confident_block` の `add` で、
  根拠に外部の成功したリクエストも内部のリクエストもないものは、人の承認なしに適用されることがあります（1 日の上限
  あり）。そのため、待っている間のスクリプトは `approved`、`applying`、`applied` も受け入れるようにしてください。

## 7. 実例：スクリプトから確定ブロックを提案する

このスクリプトは `/.env` を探るリクエストのブロックを提案し、チェックが終わるのを待って、承認者向けのリンクを表示します。
`curl`、`jq`、そして `changes:propose` と `changes:read` を持ち、送信元をスクリプトのホストに限定したトークンが必要です。

```sh
#!/bin/sh
set -eu
BASE='https://waf.example.com/api/v1'
TOKEN='jwm_example00000_EXAMPLE-not-a-real-token'

# 1. まず spec を検証する（何も作成されない）
SPEC='{"target": "path", "regex": "^/\\.env$", "msg": "dotenv probe", "source": "external"}'
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"kind\": \"confident_block\", \"spec\": $SPEC}" "$BASE/changes/preview" | jq -e '.ok' >/dev/null

# 2. 提案する
CID=$(curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{
  \"kind\": \"confident_block\", \"spec\": $SPEC,
  \"reason\": \"SIEM case 4711: /.env probes from 203.0.113.0/24\",
  \"tests\": [{\"host\": \"app.example.com\", \"path\": \"/.env\", \"source\": \"external\", \"expect\": 403},
             {\"host\": \"app.example.com\", \"path\": \"/\", \"source\": \"external\", \"expect\": 200}]
}" "$BASE/changes" | jq -er '.change_id')
echo "change $CID proposed"

# 3. 10 秒ごとに確認、最大 10 分
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

その後、人が Web 画面にサインインして**変更**（または上のリンク）を開き、チェック結果と差分を確認して承認または却下
します。スクリプトは終了状態になるまで `GET /changes/{id}` のポーリングを続けるか、`applied` と `applied_version` を
待つこともできます。
