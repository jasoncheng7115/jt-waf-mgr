# jt-waf-mgr v0.4.27

[English](README.md) · [繁體中文](README_zh-TW.md) · **日本語**

[![License](https://img.shields.io/github/license/jasoncheng7115/jt-waf-mgr?color=blue)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/jasoncheng7115/jt-waf-mgr)](https://github.com/jasoncheng7115/jt-waf-mgr/commits/main)
![Python](https://img.shields.io/badge/Python-3.11%2B%20stdlib%20only-3776AB?logo=python&logoColor=white)
![Vue](https://img.shields.io/badge/Vue-3-42b883?logo=vuedotjs&logoColor=white)
![ModSecurity](https://img.shields.io/badge/libmodsecurity-v3-1f6feb)
![OWASP CRS](https://img.shields.io/badge/OWASP%20CRS-4.x-000000)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%3A2025-000000)

**🌐 [プロジェクトサイト →](https://jasoncheng7115.github.io/jt-waf-mgr/?lang=ja)**

> **nginx + libmodsecurity v3 + OWASP CRS 4** のためのセルフホスト型 Web 管理ツールです。WAF が何をしたかを読み取り、
> 証拠の確認・サンドボックス試験・承認を経る変更フローでルールを調整し、オンプレミスの LLM にイベントを確認させ、重要な
> 事柄を Teams、Telegram、Zulip、Slack、Discord、Nextcloud Talk、メール、署名付き webhook に通知します。
>
> Jason Tools Co., Ltd. · ライセンス：AGPL-3.0

![概要](docs/shots/ja/overview.png)

---

## なぜ jt-waf-mgr？

libmodsecurity v3 には管理画面がありません。ルール、除外、ブロックはすべて設定ファイルで、調整には本番のリバースプロキシ上で
JSON 監査ログを読み、ファイルを手で編集する必要があります。jt-waf-mgr は監査ログを読める画面にし、すべての変更を信頼できる
フローにします。

- **何が起きたかが分かる**：ブロック / 記録のみを、サイト、攻撃の種類、送信元（国とネットワーク事業者を含む）、ルール、時間
  ごとに表示。「CRS スコアだけでブロック」されたものを先頭に表示します（誤検知の可能性が最も高いため）。
- **安全に変更する**：テンプレート（除外、確定ブロック、マスク、プラグイン切替、エキスパート用の生ルール）→ 静的検査（正規表現、
  ReDoS）→ アクセスログからの証拠 → 本番設定と回帰サンプルによる使い捨ての nginx サンドボックス → 承認 → 小さな root
  プログラムが試験・reload・ヘルスチェックを行い、失敗時は自動で元に戻す → バージョンはワンクリックでロールバック。
- **モデルは手伝うが、単独では決めない**：自前の OpenAI 互換 LLM サーバーによる定期分析が、探査に対する狭いブロック、誤検知に
  対する最小の除外を提案し、アラートを出します。すべてプログラムが検証し、緩和は必ず人が承認します。
- **記録を信頼できる**：ハッシュチェーンの追記専用監査記録（アンカーはデータベース外と syslog）、署名付きリリース、すべての
  nginx / ModSecurity / CRS ファイルの指紋、ISO/IEC 27001:2022・台湾の資通安全管理法・OWASP Top 10:2025 との対照。

## 機能

- **収集**：ModSecurity JSON 監査ログ（copytruncate と名前変更によるローテーション、過大・破損レコードに対応）。パスワードや
  トークンなどの機密項目は**保存前に**マスクします。
- **概要とイベント**：タイムラインをドラッグして拡大、または最長 31 日の期間を指定。絞り込み条件は URL に保持。イベント詳細で
  一致したすべてのルールを表示し、ワンクリックで除外やブロックを起案。
- **一時的な IP ブロック**（0.4.24 で追加、任意）：メールサーバーの fail2ban、SOAR プレイブック、承認者が単一アドレスを
  一時的にブロックします。1 つの nginx deny リストがすべてのサイトに効きます。[一時的な IP ブロック](#一時的な-ip-ブロック任意)を参照。
- **国別ブロック**（0.4.27 で追加、任意）：サイトを一部の国だけに限定、または一部の国をブロックします。一覧は 5 つの地域
  インターネットレジストリから毎日更新。サイトごとの制限は変更フローを通るルールです。[国別ブロック](#国別ブロック任意)を参照。
- **リクエスト量**（0.4.23 で追加）：nginx のアクセスログにあるすべてのリクエストを、サイトと時間ごとに集計します（2xx、
  3xx、4xx、5xx、403、444、429、外部、バイト数。数値のみで、IP・URL・User-Agent は保存しません）。WAF がブロックした数と
  並べて表示し、WAF の数字に分母を与えます。管理の「設定」→「リクエスト量」で有効・無効とアラートを設定します。任意の
  アラート（既定はオフ）：トラフィックの急増（そのサイトの過去 7 日間の同じ時間帯の通常量の N 倍）、または 5xx 応答の多発。
- **WAF 判定フロー**：現在の設定から、これらのサイトでリクエストがどう判定されるか（サイトごとのエンジン、スコア、しきい値、
  除外、確定ブロック）を図示。
- **ルール**：各ルールの出所（OWASP CRS とバージョン、CRS プラグイン、取り込み時のインポート、人・API トークン・イベント分析
  による変更）、日ごとのヒット数、シンタックスハイライト。0.4.23 で「作成元」を追加（絞り込みと作成元ごとの件数付き）：
  OWASP CRS、OWASP CRS プラグイン、サードパーティのプラグイン、ModSecurity 基本設定、Jason Tools（jt-waf-mgr がフォームから
  生成するルールと Jason Tools のルールパック）、サイト独自（手書きのルール：取り込み時にインポートしたもの、raw ルール、
  nginx の vhost ファイル）。
- **変更フロー**：単独の変更または一括（1 回の承認・1 バージョン・1 回の reload）、ルールファイルのアップロード、証拠、
  サンドボックス、ヘルスチェック URL、承認ルール（提案者は承認不可。シングル管理者モードで自分の緩和を承認するにはワンタイム
  コードを再入力）、厳しい条件付きの自動強化、ロールバック。
- **イベント分析（オンプレミス LLM）**：ルールが見るパスで候補をまとめ、バッチごとに JSON スキーマで形式を制約したリクエストを
  送信。提案内容はモデルではなくプログラムが決めます（アンカー付きの狭い正規表現で、一般的なパス・回帰サンプル・組織自身が
  使うパスには一致しない。除外は一つの完全一致パスと特定のルール・項目のみで、承認にはワンタイムコードが必要）。外部から
  機密・バックアップ・設定のファイル名を探る要求や、同じアドレスが多くのパスを試す要求はプログラム自身の規則で偵察と判定し、
  以前に攻撃と判定したパスは一度の「誤検知」判定では緩和しません。実行ごとの要約。
  **AI はどちらの方向にも誤ることがあります**：モデルは提案するだけで、緩和は必ず人が承認し、すべてのチェックに合格した
  強化だけが自動適用されます。使う LLM については[イベント分析：推奨する LLM](#イベント分析推奨する-llm) を参照してください。
- **対応待ちアラート**：防がれていない可能性のある攻撃、利用者に影響する誤検知、進行中の攻撃、設定の外部変更、完全性の問題、
  適用やバックアップの失敗。承認者が対応内容を記入するまで開いたままで、定期的に再通知します。
- **通知**：メール（SMTP、テキスト＋HTML）、Telegram、Microsoft Teams（Workflows / Adaptive Card）、Slack、Discord、Zulip、
  Nextcloud Talk、汎用 webhook（HMAC-SHA256 署名）。イベント × チャネルのマトリクス、チャネルごとのテスト送信、再送・上限・
  送信記録。リクエスト由来の値が書式・リンク・メンションになることはありません。
- **OWASP CRS の更新**（任意、既定はオフ）：制限付きの毎日の確認で、使用中のメジャーバージョンの最新リリースを公開から 1 週間後に
  取得し、固定した CRS リリース鍵による有効な署名があるものだけを保管します。CRS ページで使用中・最新・検証済みのバージョンを表示します。
  切り替え（または保持している旧バージョンへの戻し）は変更として扱い、両バージョンにサンドボックスで同じ最近の要求を通して比較し、人が承認し、
  root プログラムが署名を再検証して自ら展開し、crs リンクを切り替え、失敗すれば元に戻します。ロールバック用に 3 バージョンを
  保持します。CRS のないホストも同じ流れで CRS 4 をインストールできます（Include は modsecurity.conf の直後に追加）。
- **ログサーバー（syslog / SIEM）**：最大 8 か所。それぞれプロトコル（ローカルソケット、UDP、TCP、TLS）、メッセージ形式（JSON、
  CEF、LEEF 2.0、GELF 1.1、key=value）、送信内容（監査記録、WAF イベント、アラート）を選べ、キューと再送も個別。テスト送信で
  実際に送った内容を表示します。
- **アカウント**：scrypt パスワード、approver / admin は二要素認証必須、ロックアウト、履歴と期限付きのパスワードポリシー、
  アカウントの期限と見直し。API トークンはスコープと許可送信元ネットワーク付き（提案はできるが承認は不可）。ホスト上での
  復旧は[アカウントと復旧](#アカウントと復旧)を参照してください。
- **完全性とコンプライアンス**：システムチェック、コンプライアンス、毎日検証されるバックアップとダウンロード（ワンタイム
  コード）、設定変更の履歴と原因判定（jt-waf-mgr、登録済みの自動化、外部）。
- **画面**：English・繁體中文・日本語、ライト / ダーク、スマートフォンとタブレット、GeoIP（MaxMind GeoLite2、専用の制限付き
  ジョブでダウンロード）と、ページ内で描画するリクエスト発信元の世界地図（地図サービスは使いません）。

| | |
|---|---|
| ![イベント](docs/shots/ja/events.png) | ![WAF 判定フロー](docs/shots/ja/waf-model.png) |
| ![イベント分析](docs/shots/ja/analysis.png) | ![通知](docs/shots/ja/notifications.png) |
| ![アラート](docs/shots/ja/alerts.png) | ![システムチェック](docs/shots/ja/system-check.png) |

## 要件

- Debian 12 / 13 または Ubuntu 24.04（22.04 の libmodsecurity パッケージは古いため 3.0.9 以上を自分でビルド）、**Python 3.11 以上（標準ライブラリのみ、pip もパッケージも不要）**：オフラインで
  インストールできます。
- nginx と ModSecurity-nginx コネクタ、libmodsecurity 3.0.9 以上、`SecAuditLogFormat JSON`。OWASP CRS 4.x は jt-waf-mgr が
  ダウンロード・検証・インストールできます（[OWASP CRS](#owasp-crs) を参照）。監査ログは
  `copytruncate` でローテーションしてください（libmodsecurity は reload 時にファイルを開き直しません）。nginx を新しく入れる
  場合や CRS 4 がない場合は [ModSecurity インストールガイド](docs/MODSECURITY.ja.md)、インターネットに接続できないホストは
  [オフラインでのインストールと更新](docs/OFFLINE.ja.md) を参照してください。サイトのルール
  ファイルがなくても取り込めます（CRS ルールの前後に空の管理ファイルを追加します）。
- 任意：イベント分析用のネットワーク上の OpenAI 互換オンプレミス LLM サーバー（llama.cpp、vLLM、Ollama など。
  [推奨する LLM](#イベント分析推奨する-llm) を参照）、GeoIP 用の MaxMind アカウント。

## インストール

```sh
openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-0.4.27.tar.gz.sig jt-waf-mgr-0.4.27.tar.gz
tar xzf jt-waf-mgr-0.4.27.tar.gz && cd jt-waf-mgr-0.4.27
sudo ./install.sh                             # 先にすべてのファイルとリリース署名を検証
sudo jt-waf-mgr check                         # nginx / ModSecurity 設定を解析
sudo jt-waf-mgr user add alice --role admin   # 一時パスワードを表示
```

### 管理画面への接続

サービスは `127.0.0.1:8095` だけで待ち受けます（`/etc/jt-waf-mgr/config.toml` の `[server] listen`）。直接公開することは
なく、nginx の管理用 vhost から転送します。リリースは vhost の例を `/etc/jt-waf-mgr/nginx-vhost.conf.example` に
インストールします。nginx の vhost ディレクトリにコピーしてください。例：

```sh
sudo cp /etc/jt-waf-mgr/nginx-vhost.conf.example /etc/nginx/sites-available/waf.example.com.conf
sudo ln -s /etc/nginx/sites-available/waf.example.com.conf /etc/nginx/sites-enabled/
# （または /etc/nginx/conf.d/waf.example.com.conf にコピー）
```

コピーしたファイルで次を設定します：

- `server_name`：開くときの名前（例：`waf.example.com`）。
- `ssl_certificate` と `ssl_certificate_key`：証明書（下記参照）。
- `allow` の行：内部ネットワークのみ（さらに絞るなら管理者のネットワーク）。それ以外は `deny all` のままにします。

続いて `sudo nginx -t && sudo systemctl reload nginx` を実行します。この vhost は意図的に `modsecurity off` にしています。
管理画面は攻撃文字列を表示するため、WAF を有効にすると自分自身で WAF に引っかかるからです。任意：例にあるコメントアウト
された `limit_req` ブロックで、サインインの前に総当たり攻撃への歯止めを追加できます。

証明書は次のいずれか：

- 組織内部の CA、または既存のワイルドカード証明書。
- Let's Encrypt：管理サイトは内部専用なので、HTTP-01 チャレンジは通常届きません。DNS-01 チャレンジ（certbot と DNS
  事業者のプラグイン）を使うか、公開ホストで発行してコピーしてください。
- 検証環境に限り、自己署名証明書（ブラウザに警告が出ます）：

```sh
sudo openssl req -x509 -newkey rsa:3072 -nodes -days 825 -keyout /etc/ssl/private/waf.key -out /etc/ssl/certs/waf.crt -subj "/CN=waf.example.com" -addext "subjectAltName=DNS:waf.example.com"
```

その後 `https://waf.example.com`（設定した名前）を開き、`jt-waf-mgr user add` が表示した一時パスワードでサインインします。
初回のサインインでは新しいパスワードと TOTP 二要素認証の設定が必須です。運用設定（GeoIP、LLM、分析、通知、リクエスト量、
ネットワーク、ポリシー）は Web 画面で行い、`/etc/jt-waf-mgr/config.toml` には起動に必要な項目だけを置きます。

### jt-waf-mgr にルールを変更させる

jt-waf-mgr が書き込むのは ModSecurity のファイルだけで、nginx の設定は決して書き込みません。nginx の設定を読み（サイトと
ModSecurity のメイン設定ファイルを見つけるため）、`nginx -t` を実行し、nginx を reload します。管理用 vhost と nginx の
`modsecurity on;` は、管理者自身が一度だけ行う編集です。唯一の例外は任意の一時 IP ブロックのリストで、`deny` 行だけのファイルをお客様が一度 include します。

jt-waf-mgr にルールを変更させるには、適用プログラムを有効にし（`sudo ./install.sh --enable-apply`）、ヘルスチェック URL を
設定し、「ルール → 管理対象ルール」で既存のルールファイルを取り込みます（通常の変更と同様に admin が承認）。それまでは何も
書き込みません。サイトのルールファイルがなくても取り込めます。

### OWASP CRS

CRS は jt-waf-mgr が扱います。新しいホストに必要なのは、nginx と ModSecurity モジュール、`SecAuditLogFormat JSON` を含む
`modsecurity.conf`、`modsecurity.conf` を Include するメイン設定ファイル、nginx の `modsecurity on;` と
`modsecurity_rules_file …` だけです（[ModSecurity インストールガイド](docs/MODSECURITY.ja.md)）。その後：

1. CRS ページで「ここで CRS を最新に保つ」をオンにします。
2. jt-waf-mgr は最新の CRS 4.x を公開から `wait_days`（既定 7 日）経ってからダウンロードし、固定した CRS 署名鍵で検証します。
3. 「サンドボックスで比較してインストールを提案」で変更が作成されます。
4. 人が承認すると、jt-waf-mgr が `crs-<バージョン>`、`crs` リンク、`crs-setup.conf` をインストールし、`modsecurity.conf` の
   直後に Include を挿入します。
5. 続いて既存ルールの取り込みを行うと、CRS ルールの前後に jt-waf-mgr の管理ルールファイルが追加されます。

以後の CRS 更新も同じ流れです：ダウンロード、検証、サンドボックスでの比較、人による承認、インストール。ロールバック用に
3 バージョンを保持します。CRS を手動でインストールすることもできます（ガイドを参照）。

### 一時的な IP ブロック（任意）

他のシステム（たとえば Web メールがこのプロキシの後ろにあるメールサーバーの fail2ban）は、API（スコープ `blocks:write`）で
単一アドレスを一時的にブロックできます。承認者は「ブロック中の IP」ページで操作できます。jt-waf-mgr は一覧を `deny` 行
だけの nginx ファイル 1 つに書き込み、ModSecurity を使わないサイトも含めてすべてのサイトに効きます。使い方：

1. ファイルを作成し、nginx.conf の `http { }` の中で一度だけ include してから、テストして reload します：
   ```sh
   sudo install -D -m 644 /dev/null /etc/nginx/jt-waf-mgr/blocked-ips.conf
   # nginx.conf の http { } の中：   include /etc/nginx/jt-waf-mgr/blocked-ips.conf;
   sudo nginx -t && sudo systemctl reload nginx
   ```
2. 設定 → 一時的な IP ブロック：オンにし、決してブロックしないネットワーク（たとえばサイトの前の CDN）を登録します。
3. 管理 → API トークン：`blocks:write`（と `blocks:read`）を持ち、呼び出し元ホストのアドレスに限定したトークンを作ります。
4. 例：API でブロックと解除を行う fail2ban のアクション：
   ```ini
   # /etc/fail2ban/action.d/jt-waf-block.conf  (chmod 600: it holds the token)
   [Definition]
   actionban   = curl -fsS -m 10 -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
                 -d '{"ip": "<ip>", "ttl": <bantime>, "source": "<source>", "reason": "fail2ban <name>"}' <waf>/api/v1/blocks
   actionunban = curl -fsS -m 10 -X DELETE -H "Authorization: Bearer <token>" "<waf>/api/v1/blocks/<ip>?source=<source>"
   [Init]
   waf    = https://waf.example.com
   token  = jwm_...
   source = mail1/<name>
   ```
   jail では `action = jt-waf-block` を使います。`bantime` は 60 秒から 7 日の間にしてください（それより長い、または永久の
   ブロックは拒否されます）。内部アドレスは jail の `ignoreip` で除外したままにします（いずれにしても拒否されます）。
   任意で、設定 → 一時的な IP ブロック →「機密ファイルを探す送信元を自動でブロック」：1 時間以内に 5 つの異なる機密・設定ファイル名を
   要求した外部アドレスを、プログラムのルールで 24 時間ブロックします。WAF イベントを見て、拒否または見つからなかった（4xx/5xx）
   ファイル名だけを数え、少なくとも 1 つは明白な機密ファイル（.env、.git、鍵、ダンプ、バックアップ）であることが条件です。
   こうした名前に 2xx/3xx が返ったアドレスは自動でブロックせず、人の判断に任せます。変更フローを通らず全サイトでブロックするため、既定はオフです。

ブロックの既定は 24 時間、トークンからは最長 7 日、手動では最長 30 日で、永久ブロックはありません。内部ネットワーク、
既知のスキャナー、信頼するプロキシ、保護リストは決してブロックされません。nginx は `real_ip` 後のアドレスで判定するため、
CDN の後ろのサイトには `set_real_ip_from` / `real_ip_header` が必要です。独自の `allow` / `deny` を持つ server と location は
このリストを継承しません（「ブロック中の IP」ページに表示）。ブロックは約 1 分以内に新しいリクエストに効きます。すでに開いている接続（WebSocket）は閉じるまで続きます。詳しくは [API マニュアル](docs/API.ja.md) の 4.9 節を参照してください。

### 国別ブロック（任意）

リクエストの送信元の国で個々のサイトを制限します。列挙した国だけを許可する（例：「台湾と日本のみ」）か、列挙した国を
ブロックします。各制限は ModSecurity のルールで、ほかのルールと同じく変更フロー（チェック、サンドボックス、承認、ロールバック）
を通ります。アドレス一覧はデータであり、更新は変更フローを通りません。

1. 設定 → 国別ブロック：オンにして「今すぐ更新」。別の制限付きジョブが 5 つのレジストリの delegated ファイル（APNIC、ARIN、
   RIPE NCC、LACNIC、AFRINIC、合計約 28 MB）をダウンロードし、各レジストリの MD5 ファイルとファイル自身の件数で検証して、
   5 つすべてが通ったときだけ一覧を置き換えます。以後は 1 日 1 回。Web サービス自体は外部に接続しません。
2. 変更 → 新規 → 国別ブロック：サイト、「これらの国のみ許可」または「これらの国をブロック」、国を選びます。チェックはアクセス
   ログから、このルールがブロックしたはずのリクエスト数とアドレス数、そのうち 2xx/3xx で応答されたもの（締め出される実際の
   利用者）を数えます。サンドボックスは許可される国、ブロックされる国、内部からのリクエストを 1 つずつテストします。
3. 承認後、root の適用プログラムがルールの読む一覧（`/etc/nginx/modsec/jt-waf-mgr/countries/`）を書き、nginx をテストして reload します。

決してブロックしないもの：内部ネットワーク、既知のスキャナー、信頼するプロキシ、保護リスト（設定 → 一時的な IP ブロック）。
サイトの前にある CDN が締め出されることはありません。CDN の後ろのサイトには `set_real_ip_from` / `real_ip_header` が必要です。
ルールは ModSecurity で動くため、`modsecurity off` の location は対象外です。レジストリのデータはアドレスブロックの登録国であり、
利用者の実際の所在地ではありません（VPN、クラウドのリージョン、ローミング中の携帯は別の場所のことがあります）。

### アカウントと復旧

ホスト上で root として実行します：

```sh
sudo jt-waf-mgr user list                       # アカウント、ロール、状態（disabled、totp、must-change）
sudo jt-waf-mgr user add alice --role approver  # ロール：viewer（既定）、operator、approver、admin
sudo jt-waf-mgr user unlock alice
sudo jt-waf-mgr user reset alice
sudo jt-waf-mgr user passwd alice
sudo jt-waf-mgr user disable alice              # および enable
```

- `add`：一時パスワードを表示します。初回サインインで変更が必要です。
- `unlock`：サインイン失敗によるロックを解除します。
- `reset`：新しい一時パスワードを発行し、TOTP を消去し、サインイン時にパスワード変更を強制します。スマートフォンを
  なくしたときの復旧方法です。
- `passwd`：対話形式でパスワードを設定します。
- `disable` と `enable`：アカウントを無効化・再度有効化します。
- これらの変更はすべて監査記録に残ります。

### アップグレード

```sh
sudo ./upgrade.sh --check     # すべての検査のみ、何も変更しない
sudo ./upgrade.sh             # バックアップ、切替、検査。どこかで失敗すれば自動で元に戻す
sudo ./upgrade.sh --rollback  # 後で必要なら：アップグレード前のバージョン（とデータベース）に戻す
sudo jt-waf-mgr doctor        # いつでも健全性を確認
```

アップグレードはインストール済みのプログラムと固定された鍵で新しいリリースを検証し、変更の適用中は拒否し、
`/var/backups/jt-waf-mgr/` にバックアップを残し、すべてのアップグレード（とロールバック）を監査記録に残します。

### アンインストール

```sh
sudo ./uninstall.sh           # サービスとプログラムを削除し、データと設定は残す
sudo ./uninstall.sh --purge   # /var/lib/jt-waf-mgr、/etc/jt-waf-mgr と jtwaf ユーザーも削除
```

nginx の設定には触れません。管理画面の vhost はご自身で削除してください。既存のルールファイルを取り込んでいた場合、
`/etc/nginx/modsec/jt-waf-mgr/` の管理ファイルはそのまま残り、nginx は引き続き読み込みます。以後は手動で保守してください。

## イベント分析：推奨する LLM

分析は常に自前のオンプレミス LLM サーバーで行います。

- **サーバー**：OpenAI 互換（llama.cpp server、vLLM、Ollama）で、JSON スキーマで形式を制約した回答に対応しているもの。
  対応していない場合は通常の JSON モードを使い、回答の信頼性が下がります。
- **モデル**：約 14B パラメータ以上の指示（instruct）モデルで、4 ビット量子化以上。27–32B の dense モデルか 30B 級の MoE を
  推奨します。バージョン：Qwen は 3.8 以上、Gemma は 4 以上（それより古いものは推奨しません）、または gpt-oss-20b。
- **コンテキスト長**：16k トークン以上。実測：候補 11 件の 1 バッチで入力約 3k、出力約 3.5k トークンを使い、本番サーバーで
  約 85 秒かかりました。
- **小さなモデル**（8B 以下）や 2–3 ビット量子化は、実行ごとの判定が矛盾しやすくなります。本番では 3 ビット量子化のモデルが
  同じ探査を 2 回は攻撃、1 回は誤検知と判定しました。jt-waf-mgr はスキャナーのパターンに対するプログラム側の規則と判定履歴で
  これを補いますが、より強いモデルのほうが有利です。
- **遅いハードウェア**：「設定」で LLM のタイムアウトを延ばしてください（最大 900 秒）。

AI は誤ることがあります。自動適用は強化（許可 → ブロック）だけで、緩和は必ず人が承認します。

## 連携用 API

SIEM、SOAR のプレイブック、スクリプトは API トークンで接続します（admin が作成し、スコープと許可する送信元アドレス付き。
トークンは変更を提案できますが、承認はできません）。[API 連携マニュアル](docs/API.ja.md)を参照してください。

## セキュリティ（OWASP Top 10:2025）

[SECURITY.md](SECURITY.md) と [docs/COMPLIANCE.md](docs/COMPLIANCE.md) を参照してください。脆弱性は非公開で報告してください。

- Web サービスは loopback のみで待ち受け、非特権で動作し、外部に接続しません。root で動くのは適用プログラムだけで、すべての
  リクエストを再検証し（許可されたディレクティブのみ、チェックサム、ディスク上の手動変更なし）、管理対象のファイルだけを書き
  込みます。GeoIP のダウンロード、LLM 分析、通知はそれぞれ専用の制限付きワンショットユニットで動きます。
- `unsafe-inline` を許可しない厳格な CSP。リクエスト由来の内容（URL、User-Agent、一致したデータ、モデルの文章）はすべて
  テキストとして表示します。
- 機密値はデータベースに入る前にマスクし、設定内のシークレットは書き込み専用です。
- A01：ロール viewer / operator / approver / admin、API トークンのスコープと送信元ネットワーク。トークンは承認できません。
- A04 / A07：scrypt、リプレイ防止付き TOTP、ロックアウト、機密操作のワンタイムコード（試行回数制限）。
- A08：署名付きリリースマニフェストをインストーラー・サービス・適用プログラムが検査。ハッシュチェーンの監査記録。
- A09：すべての書き込みを監査し、syslog にも送信（1 行の JSON、制御文字はエスケープ）。
- すべてのリリースはテスト計画（[TEST_PLAN.md](TEST_PLAN.md)）に合格する必要があります：単体テスト、全ページのブラウザ試験、
  全ルートのセキュリティ検査、OWASP ZAP のアクティブスキャン、独立レビュー、アップグレードとロールバックの試験。

## 技術

| 層 | 選択 |
|------|--------|
| バックエンド | Python 3.11+ 標準ライブラリ（http.server、sqlite3、hashlib.scrypt、tomllib、urllib、smtplib） |
| データベース | SQLite（WAL）、監査テーブルはトリガーで追記専用 |
| フロントエンド | Vue 3 · Vite · 独自 i18n（実行時コンパイルなし、CSP 対応）· Iconoir アイコン |
| WAF | nginx · libmodsecurity v3 · ModSecurity-nginx · OWASP CRS 4 |
| デプロイ | systemd ユニット（サービス、適用、GeoIP、分析、通知）。Docker 不要 |

## ディレクトリ構成

```
jt-waf-mgr/
├── jtwafmgr/            # 本体（収集、Web API、変更フロー、適用、分析、通知、完全性）
│   ├── collector/       # ModSecurity 監査ログの読み取り
│   ├── web/             # HTTP サーバーとルート
│   └── static/          # ビルド済みの Web 画面
├── frontend/            # Web 画面の Vue 3 ソース
├── deploy/              # systemd ユニット、nginx の例、リリース公開鍵、Wazuh ルール案、ZAP 基準
├── docs/                # 仕様、API 契約、コンプライアンス対照、プロジェクトサイト
├── tests/               # 単体・統合テスト（合成データのみ）
├── tools/               # ビルド、リリース、preflight、ブラウザ試験、セキュリティ検査、ZAP スキャン
├── install.sh · upgrade.sh · uninstall.sh
└── TEST_PLAN.md · TEST_CHECKLIST.md · SECURITY.md · CHANGELOG.md
```

## ライセンス

AGPL-3.0。変更したバージョンをネットワークサービスとして提供する場合は、利用者がソースコードを入手できるようにしてください
（未変更版はフッターのリンクで提供しています）。
