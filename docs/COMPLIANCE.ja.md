# コンプライアンス対応表

[English](COMPLIANCE.md) · [繁體中文](COMPLIANCE.zh-TW.md) · **日本語**

この文書では、jt-waf-mgr が一般的なセキュリティ管理策をどのように支えているか、また運用する組織が引き続き自ら行う必要があることを説明します。
ここに記載しているのは、プログラムが実際に行っていることだけです。UI の「コンプライアンス」ページ（admin）は、現在の設定から各項目の状態をその場で算出します。この文書はその対応の根拠を説明するものです。

参照している規範：
- **ISO/IEC 27001:2022** 附属書 A
- **台湾 資通安全管理法**（Cyber Security Management Act）：情報システムの防護基準（資通系統防護基準、資通安全責任等級分級辦法の附表十）。項目名はこの附表に従っています。
  - どの措置が適用されるかは、システムの防護レベル（普/中/高）によって異なります。
  - 評価の際は、主管機関が公表している最新版を確認してください。
- **OWASP Top 10:2025**

防護レベルは `/etc/jt-waf-mgr/config.toml` で設定します：

```toml
[compliance]
level = "medium"     # "", "low", "medium", "high"
```

この設定は動作を何も変えません。「コンプライアンス」ページが、そのレベルで求められる水準に満たない設定を表示するようになるだけです。

## アクセス制御

### アカウント管理（account_management）
ISO A.5.16, A.5.18 · 資安法 存取控制－帳號管理 · OWASP A01
- ローカルアカウントには 4 つのロールがあります。
- アカウントは終了日（`expires_at`）を指定して作成でき、その日を過ぎると自動的に無効化されます。
- `auth.dormant_days`（デフォルト 90）日間サインインのないアカウントは無効化されます。最後の有効な admin が無効化されることはありません。
- アカウントレビュー：`GET /api/v1/users/review` と「アカウントレビュー」画面に、次のものが一覧表示されます：
  - すべてのアカウント：ロール、状態、最終サインイン（日時とアドレス）、最終操作からの日数；
  - すべての有効な API トークン。
- レビューのたびに監査記録が 1 件書き込まれます。レビューの記録として CSV または JSON でダウンロードできます。
- アカウントのあらゆる変更が監査されます：作成、ロール、無効化/有効化、リセット、ロック解除、有効期限、セッションの取り消し。

### 最小権限（least_privilege）
ISO A.5.15, A.8.2, A.8.3 · 資安法 存取控制－最小權限 · OWASP A01
- ロール：
  - viewer：閲覧；
  - operator：変更の提案；
  - approver：承認とロールバック；
  - admin：ルールファイルの取り込み、アカウント、トークン、設定の管理。
- API トークンにはスコープと許可された送信元ネットワークがあります。承認、トークンの管理、設定の変更は決してできません。

### 職務の分離（segregation_of_duties）
ISO A.5.3, A.8.32 · OWASP A06
- 変更の提案者は、その変更を承認できません。
- 緩和する変更には必ず人の承認が必要です。トークンは提案しかできません。
- 単独管理者モード（管理者が 1 人だけのサイト向け）は、明示的で監査される設定です。このモードで自分の緩和変更を承認するには、OTP の再入力と理由の記入が必要です。

### セッションタイムアウト（session_timeout）
ISO A.8.5 · 資安法 存取控制－帳號管理 · OWASP A07
- 2 種類のタイムアウト：
  - アイドルタイムアウト：`server.session_idle_minutes`、デフォルト 30 分；
  - 絶対タイムアウト：`server.session_max_hours`、デフォルト 12 時間。
- ユーザーごとのセッション数には上限があります（`auth.max_sessions_per_user`）。
- ユーザーは自分のセッションを確認して終了できます。admin はユーザーをすべての場所からサインアウトさせることができます。

## 識別と認証

### 認証（authentication）
ISO A.5.17, A.8.5 · 資安法 識別與鑑別－身分驗證管理 · OWASP A07
- パスワードは scrypt でハッシュ化されます。一時パスワードは初回サインイン時に変更が必要です。
- ポリシー（すべて `[auth]` で設定可能）：
  - 最小長：12；
  - 文字種：4 種類のうち 3 種類；
  - 直近 N 回のパスワードと同じでないこと：3；
  - 任意の最大有効期間（期限切れの場合はサインイン時に変更を強制）と最小有効期間。
- `lockout_threshold` 回失敗すると `lockout_minutes` 分間ロックアウトされます（5 回/15 分）。
  - ロックアウトは syslog の優先度 crit で監査されます。
  - さらに、送信元アドレスごとのレート制限もあります。
- 中・高レベルのシステム：`password_max_age_days` と `password_min_age_hours` を設定してください。

### 多要素認証（multi_factor）
ISO A.8.5 · 資安法 識別與鑑別－內部使用者之識別與鑑別 · OWASP A07
- TOTP（RFC 6238）、リプレイ対策あり。
- デフォルトでは approver と admin に必須です（`auth.require_totp_roles`）。
- 高レベルのシステム：すべてのロールに必須にしてください。

### 認証情報のフィードバック（auth_feedback）
ISO A.8.5 · 資安法 識別與鑑別－鑑別資訊回饋 · OWASP A07
- パスワードと OTP の入力はマスクされます。
- 存在しないユーザーとパスワードの誤りは、同じ応答を同じ時間で返します。
- サインイン後、ユーザーには前回のサインイン（日時、アドレス）と、それ以降の失敗回数が表示されます。

## ログ記録と説明責任

### 監査記録（audit_logging）
ISO A.8.15 · 資安法 記錄事件、日誌紀錄內容 · OWASP A09
- すべての操作は監査記録の 1 行となり、日時、操作者、操作者の種類（ユーザー/トークン/システム）、送信元アドレス、アクション、結果、詳細を含みます。
- 対象となる操作：
  - サインイン、サインアウト、失敗とロックアウト；
  - アカウント、トークン、設定の変更；
  - すべての変更の提案、チェック、承認、却下、適用、ロールバック；
  - エクスポート、レビュー、バックアップ、完全性チェックの結果。
- 同じ記録が 1 行の JSON として syslog にも送られます（プログラム名 `jt-waf-mgr:`）。その行の id とハッシュが付きます。
- API のすべての書き込みルートを順に確認するテストがあり、監査を行わないルートがあると失敗します。

### ログの保護（log_protection）
ISO A.8.15, A.5.33 · 資安法 日誌資訊之保護 · OWASP A09
- **ハッシュチェーン**：各行に `sha256(previous hash + canonical row)` が保存されます。行を変更、挿入、削除するとチェーンが壊れます。
- **追記専用**：監査テーブルはデータベースのトリガーによって追記専用になっています。
  - 保存期間（`retention.audit_days`）のデフォルトは 0、つまり永久保存です。
  - 保存期間による削除は最も古い行だけを取り除き、チェーンを検証可能なまま保ちます。
- **アンカー**：5 分ごとに最新の（id、ハッシュ）を `/var/lib/jt-waf-mgr/audit-anchors.jsonl` に追記し、syslog にも送ります。
  - このファイルは追記専用（`chattr +a`）で、サービスユーザーは行を変更・削除できません。
  - コンテナ（LXC）内ではこのフラグを設定できません。コンテナには CAP_LINUX_IMMUTABLE がなく、インストーラーが警告を出します。ホスト側から設定してください。例えば Proxmox では：
    `chattr +a /proc/$(lxc-info -n <CTID> -p -H)/root/var/lib/jt-waf-mgr/audit-anchors.jsonl`。
    このフラグはファイルシステムに保存され、再起動後も保持されます。設定できない場合、SIEM にある syslog のアンカーが唯一の独立したコピーになります。
  - データベースから書き換えられたチェーンは、アンカーと一致しなくなります。
- 検証のタイミング：
  - 5 分ごと（差分）；
  - 毎日（全体）；
  - 必要なときに随時（監査ページの「チェーンを検証」）；
  - コマンドライン（`jt-waf-mgr integrity`）。
- 失敗すると、監査記録 `integrity.audit_chain_failed` が syslog の優先度 crit で書き込まれます。

### ログ処理の失敗への対応（log_failure_response）
ISO A.8.16 · 資安法 日誌處理失效之回應 · OWASP A09
- syslog の送信エラーは数えられ、「システムチェック」ページに表示されます。
- 完全性チェックの失敗、バックアップの失敗、ロックアウトは優先度 crit で記録されるため、SIEM でアラートを出せます。問題が続く間は 12 時間ごとに繰り返し記録されます。

### ログの保存容量（log_capacity）
ISO A.8.6 · 資安法 日誌儲存容量
- データベースのある場所の空き容量を確認します（`integrity.disk_min_free_mb`）。
- データの種類ごとに保存期間を設定できます：
  - イベント：`retention.events_days`（30）；
  - 統計：`retention.stats_days`（365）；
  - 監査：`retention.audit_days`（0 = 永久）。

### タイムスタンプと時刻同期（time_sync）
ISO A.8.17 · 資安法 時戳及校時
- 「システムチェック」ページに、時計が NTP と同期しているかどうかが表示されます。
  - 情報源は systemd-timedated で、systemd-timesyncd と chrony のどちらでも動作します。
- すべての記録のタイムスタンプにはオフセットが付きます。

### SIEM への転送（siem_forwarding）
ISO A.8.16 · 資安法 資通系統監控
- syslog（デフォルトのファシリティは `local0`）が、すべての監査記録とアンカーを運びます。
- SIEM への転送は rsyslog/journald で設定します。これは組織としての管理措置です。

### 証拠のエクスポート（evidence_export）
ISO A.5.28
- `GET /api/v1/audit/export`（admin）：NDJSON 形式でエクスポートします：
  - 各行のハッシュ付き；
  - 最後の行は、全行に対する SHA-256 を含む要約です。
- `jt-waf-mgr audit-verify FILE` でエクスポートをオフライン検証できます。
- イベントのエクスポート（`/events/export`）にも SHA-256 が付きます。

## 完全性、構成と変更

### ソフトウェアの完全性（software_integrity）
ISO A.8.19, A.8.32 · 資安法 軟體及資訊完整性 · OWASP A08, A03
- **リリース**：`release/MANIFEST.sha256`（全ファイルの SHA-256）を含み、リリース鍵（RSA-3072）で署名されています。
- **インストール時**：インストーラーはインストール前にすべてのファイルと署名を検証し、初回インストール時に鍵を固定（pin）します。
- **実行時**：サービスは 1 時間ごとに、root の適用プログラムは毎回の実行前に確認します。
  - 確認の対象：インストール済みのファイル（パッケージ、systemd unit、コマンドラッパー）が署名付きマニフェストと一致すること。
  - パッケージディレクトリに余分なファイルがある場合も失敗とみなします。
  - 確認に失敗した場合、適用プログラムは動作を拒否します。
- **アップグレード前**：`jt-waf-mgr verify-release <unpacked dir>`。
- SBOM：すべてのリリースに `sbom.cdx.json`（CycloneDX 1.5）が含まれます。

### 構成管理（configuration_management）
ISO A.8.9 · OWASP A02
- 5 分ごとに、次のもののフィンガープリント（SHA-256）を取ります：
  - すべての nginx/ModSecurity/CRS ファイル；
  - nginx のバイナリ；
  - ModSecurity モジュール。
- 変更のたびに、追加・削除・変更されたファイルを保存し、その原因を判定します：
  - jt-waf-mgr（適用されたバージョン）；
  - 外部。
- 外部からの変更は監査され（`config.changed`、結果 `outside`）、「構成の変更」に一覧表示されます。
- 管理対象のルールファイルには SHA-256 のヘッダーが付いています。手動の編集は検出され、適用プログラムはそれを上書きしません。

### 変更管理（change_management）
ISO A.8.32, A.8.31 · 資安法 系統發展生命週期 · OWASP A06
- すべてのルール変更は、次の手順を経ます：
  1. 静的チェック（正規表現の妥当性、ReDoS、ID の範囲、禁止ディレクティブ）；
  2. アクセスログからの裏付け；
  3. サンドボックス（本番の構成に変更を加えた使い捨ての nginx で、テストケースと回帰サンプルを実行）；
  4. 承認；
  5. root プログラムによる適用：`nginx -t`、reload、確認、ヘルスチェック、そして失敗時の自動復元。
- バージョンは保持され、ロールバックできます。

### バックアップ（backup）
ISO A.8.13 · 資安法 營運持續計畫－系統備份
- データベースは毎日バックアップされます：
  - SQLite のオンラインバックアップ；
  - コピーに対する `integrity_check`；
  - SHA-256 ファイル；
  - モード 0600。
- バックアップは `backup.keep_days`（14）日間保持されます。
- バックアップの作成と検証は必要なときに随時行えます（UI、`jt-waf-mgr backup`、`jt-waf-mgr backup --verify FILE`）。
- 各バージョンの管理対象 nginx ファイルは、適用プログラムが保持します（`spool/backups`）。
- バックアップをホストの外へコピーすることは、組織としての管理措置です。

## データ保護

### データのマスキング（data_masking）
ISO A.8.11, A.8.12 · 資安法 資料儲存之安全
- 機密性の高いリクエストフィールド（`waf.sensitive_fields`：password、token、otp、secret など）の値は、何かを保存する前にマスクされます。
- マスクの対象は、引数、一致したデータ、URL です。
- 元の値を返す API はありません。

### 保存データ（data_at_rest）
ISO A.8.24 · 資安法 資料儲存之安全
- データベースはモード 0600 で、サービスユーザーが所有する 0700 のディレクトリにあります。
- jt-waf-mgr はデータベースを暗号化しません。Python 標準ライブラリには AES がないためです。データベースには機密性の高いリクエスト値は含まれません（上記参照）。
- 高レベルのシステム：ディスク暗号化を使用してください（組織としての管理措置）。

### 通信（transport）
ISO A.8.24, A.8.20 · 資安法 傳輸之機密性與完整性
- サービスはループバックでのみ待ち受けます。
- 管理用 vhost が TLS を終端します（1.2/1.3、HSTS）。`deploy/nginx-vhost.conf.example` を参照してください。
- cookie は `Secure` で、`__Host-` プレフィックスを使います。

### 保存期間（retention）
ISO A.8.10
- イベント、統計、監査記録は、設定された保存期間を過ぎると削除されます。
- バックアップは `backup.keep_days` を過ぎると削除されます。

## 開発と運用

### セキュアな開発（secure_development）
ISO A.8.25, A.8.26, A.8.28, A.8.29 · 資安法 系統發展生命週期 · OWASP A03, A05, A10
- サードパーティの Python パッケージは使用しません。
- `unsafe-inline` を許可しない厳格な CSP。`v-html` は使用しません。
- SQL はすべてパラメーター化し、`shell=True` は使用しません。
- 単体テストと API テストがあり、認可と監査の網羅性も含みます。
- リリース前の preflight で、非公開データと秘密情報をスキャンします。

### 脆弱性管理（vulnerability_management）
ISO A.8.8 · 資安法 漏洞修復
- nginx、CRS、ModSecurity のバージョンが UI に表示されます。
- オペレーティングシステム、nginx、CRS へのパッチ適用は、組織としての管理措置です。
- jt-waf-mgr の脆弱性は、[SECURITY.md](../SECURITY.md) の説明に従って報告してください。

### 監視（monitoring）
ISO A.8.16, A.8.20 · 資安法 資通系統監控
- jt-waf-mgr は WAF 自身のイベントを収集して表示します。

## 組織が行う必要があること

- syslog を、追記のみ可能なストレージを持つ別の SIEM に転送し、次のものに対してアラートを設定してください：
  - `integrity.*`；
  - `backup.failed`；
  - `account.locked`；
  - `config.changed`（結果 `outside`）。
- 定期的にアカウントをレビューし（ユーザー → アカウントレビュー）、ダウンロードした記録を保管してください。
- 毎日のデータベースバックアップをホストの外へコピーしてください。年に一度は復元をテストしてください。
- 管理用 vhost は管理用ネットワークに限定したままにしてください。
- オペレーティングシステム、nginx、libmodsecurity、CRS にパッチを適用してください。
- ホストの時計を NTP と同期させておいてください。
- リリースの秘密鍵は本番ホストに置かないでください。インストールするのは公開鍵だけです。

## 検証方法

```sh
jt-waf-mgr integrity                        # program files (signed manifest) + audit chain + anchors
jt-waf-mgr verify-release ./jt-waf-mgr-X.Y.Z   # an unpacked release, with the pinned key
jt-waf-mgr audit-verify export.ndjson       # an audit export, offline
jt-waf-mgr backup --verify jt-waf-mgr-YYYYMMDD-HHMMSS.db
cd /usr/lib/jt-waf-mgr && sha256sum -c --ignore-missing release/MANIFEST.sha256
openssl dgst -sha256 -verify /etc/jt-waf-mgr/release-key.pem \
    -signature /usr/lib/jt-waf-mgr/release/MANIFEST.sha256.sig /usr/lib/jt-waf-mgr/release/MANIFEST.sha256
lsattr /var/lib/jt-waf-mgr/audit-anchors.jsonl   # shows the a (append-only) flag
```

データの保存場所：
- データベース：`/var/lib/jt-waf-mgr/jt-waf-mgr.db`。次のものを保持しています：
  - イベント（マスク済み）、統計；
  - 監査記録、アカウント；
  - 変更、バージョン、構成のスナップショット。
- アンカー：`/var/lib/jt-waf-mgr/audit-anchors.jsonl`。
- バックアップ：`/var/lib/jt-waf-mgr/backups/`。
- 管理対象の nginx ファイル：`/etc/nginx/modsec/jt-waf-mgr/`。以前のバージョンは `/var/lib/jt-waf-mgr/spool/backups/` にあります。
- 構成：`/etc/jt-waf-mgr/config.toml`。
- 固定されたリリース鍵：`/etc/jt-waf-mgr/release-key.pem`。
