# ModSecurity インストールガイド（nginx + libmodsecurity v3 + OWASP CRS 4）

[English](MODSECURITY.md) · [繁體中文](MODSECURITY.zh-TW.md) · **日本語**

nginx だけがある（またはまだ何もない）ホストから、jt-waf-mgr が必要とする ModSecurity 環境を構築する手順です。
用意するのは nginx、ModSecurity モジュール、`modsecurity.conf` とメイン設定ファイルです（第 1–5 節）。OWASP CRS はその後
jt-waf-mgr に任せます。jt-waf-mgr が CRS 4 をダウンロード・検証・インストールし、承認された変更を通じて最新に保ちます（第 6 節、
推奨する方法）。CRS を手動でインストールすることもできます（第 7 節）。すでに ModSecurity を運用しているサイトは、第 8 節の
最後にある「jt-waf-mgr に必要な設定」と照らし合わせるだけで構いません。

jt-waf-mgr が書き込むのは ModSecurity のファイルだけで、nginx の設定は決して書き込みません。nginx の設定を読み（サイトと
ModSecurity のメイン設定ファイルを見つけるため）、`nginx -t` を実行し、nginx を reload します。nginx の `modsecurity on;`
（第 3 節）と管理用 vhost（[README](../README_ja.md#管理画面への接続)）は、管理者自身が一度だけ行う編集です。

> まず検知のみ（`DetectionOnly`）で稼働させ、jt-waf-mgr でしばらくイベントを確認して誤検知に対処してから、
> ブロック（`On`）に切り替えてください。

## 1. システムとパッケージ

- Debian 12 / 13：`libnginx-mod-http-modsecurity`。libmodsecurity 3.0.9 以上が一緒に入ります。
- Ubuntu 24.04：`libnginx-mod-http-modsecurity`。libmodsecurity 3.0.12（パッケージ名 `libmodsecurity3t64`）。
- Ubuntu 22.04：パッケージの libmodsecurity が 3.0.9 より古いため、24.04 を使うか自分でビルドしてください。

```sh
sudo apt install nginx libnginx-mod-http-modsecurity
apt-cache policy libmodsecurity3 libmodsecurity3t64   # バージョンが 3.0.9 以上であること
nginx -V 2>&1 | head -1                                # ディストリビューションの nginx であること
ls /etc/nginx/modules-enabled/ | grep -i modsecurity    # モジュールが読み込まれていること
```

コネクタモジュールは、動いている nginx と同じビルドのものでなければなりません。nginx.org のパッケージを使っている場合、
ディストリビューションのモジュールは読み込めません。ディストリビューションの nginx を使うか、同じバージョンの nginx の
ソース（`./configure --with-compat --add-dynamic-module=ModSecurity-nginx`）で動的モジュールをビルドしてください。

ディストリビューションの `modsecurity-crs` パッケージは CRS 3.3 なので**インストールしないでください**。CRS 4 は
jt-waf-mgr がインストールします（第 6 節）。手動でインストールすることもできます（第 7 節）。

## 2. ModSecurity の基本設定

設定は `/etc/nginx/modsec/` に置きます。`modsecurity.conf-recommended` と `unicode.mapping` は、ModSecurity の
ソースのうち **お使いの libmodsecurity と同じバージョン** のタグから取得します
（[github.com/owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)）。

```sh
sudo install -d -m 755 /etc/nginx/modsec
V=3.0.9   # apt-cache policy に表示されたバージョン
cd /etc/nginx/modsec
sudo curl -fLo modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/modsecurity.conf-recommended
sudo curl -fLO https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/unicode.mapping
```

`modsecurity.conf` で次の行を確認または変更します：

```apache
SecRuleEngine DetectionOnly          # 最初は記録のみ。様子を見てから On
SecAuditEngine RelevantOnly
SecAuditLogType Serial
SecAuditLogFormat JSON               # jt-waf-mgr は JSON 形式を読みます
SecAuditLog /var/log/modsecurity/modsec_audit.log
```

`SecAuditLogParts` はファイルの元の値のままで構いません。リクエスト中の機密値（パスワード、トークン、Cookie など）は
jt-waf-mgr がデータベースに書き込む前にマスクします。

## 3. メイン設定ファイルと nginx

`/etc/nginx/modsec/main.conf`：

```apache
Include /etc/nginx/modsec/modsecurity.conf
```

推奨する方法ではこの 1 行だけで十分です。jt-waf-mgr が CRS をインストールするときにこの行の直後へ CRS の Include を挿入し、
取り込み時に CRS ルールの前後へ jt-waf-mgr の管理ルールファイルを追加します。サイト独自のルールファイルは任意で（第 7 節）、
なくても取り込めます。

nginx の `http { }`（全サイト）または個別の `server { }` に追加します：

```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

## 4. 監査ログのディレクトリとローテーション

```sh
sudo install -d -m 750 -o root -g adm /var/log/modsecurity
```

`/etc/logrotate.d/modsecurity`（libmodsecurity は reload 時にファイルを開き直さないため `copytruncate` を使います）：

```
/var/log/modsecurity/modsec_audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

## 5. nginx の確認

```sh
sudo nginx -t && sudo systemctl reload nginx
```

CRS がまだない状態ではルールがないため、何も記録されません。リクエストによるテストは CRS のインストール後に第 8 節で行います。

## 6. jt-waf-mgr による OWASP CRS 4 のインストール（推奨）

1. [README](../README_ja.md#インストール) のとおりに jt-waf-mgr をインストールし、管理画面に接続して、適用プログラムを
   有効にします（`sudo ./install.sh --enable-apply`）。`sudo jt-waf-mgr check` で見つかったメイン設定ファイルが表示されます。
2. CRS ページで「ここで CRS を最新に保つ」をオンにします。
3. jt-waf-mgr は最新の CRS 4.x を公開から `wait_days`（既定 7 日）経ってからダウンロードし、固定した CRS 署名鍵で検証します。
4. 「サンドボックスで比較してインストールを提案」で変更が作成されます。
5. 人が承認すると、jt-waf-mgr が `crs-<バージョン>`、`crs` リンク、`crs-setup.conf` をインストールし、`modsecurity.conf` の
   直後に Include を挿入します。`main.conf` は次のようになります：

   ```apache
   Include /etc/nginx/modsec/modsecurity.conf
   Include /etc/nginx/modsec/crs-setup.conf
   Include /etc/nginx/modsec/crs/rules/*.conf
   ```

6. 続いて取り込み（「ルール → 管理対象ルール」、通常の変更と同様に admin が承認）を行うと、CRS ルールの前後に jt-waf-mgr の
   管理ルールファイル（`/etc/nginx/modsec/jt-waf-mgr/before-crs.conf` と `after-crs.conf`）が追加されます。

以後の CRS 更新も同じ流れです：ダウンロード、検証、サンドボックスでの比較、人による承認、インストール。ロールバック用に
3 バージョンを保持します。

## 7. 別の方法：CRS を手動でインストール

[CRS の GitHub releases](https://github.com/coreruleset/coreruleset/releases) から最新の 4.x リリースと対応する `.asc`
署名をダウンロードし、CRS のドキュメントに従って `gpg --verify` で検証してから展開します：

```sh
CRS=4.x.y                                # 実際のバージョン
cd /etc/nginx/modsec
sudo tar xzf ~/coreruleset-$CRS.tar.gz   # ファイル名と展開後のディレクトリ名は releases ページのとおり
sudo ln -sfn coreruleset-$CRS crs        # CRS の更新はリンクを差し替えるだけ
sudo cp crs/crs-setup.conf.example crs-setup.conf
```

このとき `/etc/nginx/modsec/main.conf` は次のとおりです：

```apache
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs-setup.conf
# 任意：サイト独自のルール（CRS ルールの前と後）
Include /etc/nginx/modsec/site-before-crs.conf
Include /etc/nginx/modsec/crs/rules/*.conf
Include /etc/nginx/modsec/site-after-crs.conf
```

2 つのサイトファイルは任意です。サイト独自のルール（除外、ブロック）用で、最初は空で構いません
（`sudo touch /etc/nginx/modsec/site-before-crs.conf /etc/nginx/modsec/site-after-crs.conf`）。これらがない場合、取り込み時に
CRS ルールの前後へ空の管理ファイルを追加します。ある場合は、中のルールをそのまま取り込み、`main.conf` は jt-waf-mgr が管理する
ファイルを読み込むように変わります。いずれの場合も以後のルール変更はすべて jt-waf-mgr のワークフローを通り、CRS の更新も
第 6 節のように jt-waf-mgr に任せられます。

## 8. テスト

```sh
sudo nginx -t && sudo systemctl reload nginx
curl -s -o /dev/null -w '%{http_code}\n' 'http://localhost/?q=<script>alert(1)</script>'
sudo tail -n 1 /var/log/modsecurity/modsec_audit.log | python3 -m json.tool | head -20
```

検知のみのモードでは応答コードは通常どおり（例えば 200）で、監査ログに CRS のルール番号を含む JSON が 1 件記録されます。

jt-waf-mgr に必要な設定：

- `SecAuditLogFormat JSON`、かつ `SecAuditEngine` が `Off` でないこと。
- `modsecurity.conf` を Include するメイン設定ファイルがあり、nginx の `modsecurity on;` と `modsecurity_rules_file` で
  読み込まれていること。
- 監査ログのディレクトリを `adm` グループが読めること。
- OWASP CRS 4 が jt-waf-mgr（第 6 節）または手動（第 7 節）でインストールされていること。

## 9. 確認してブロックに切り替える

`sudo jt-waf-mgr check` を実行すると、見つかったメイン設定ファイル、CRS のバージョンとルール数、上記の要件を満たさない設定が
表示されます。しばらく様子を見て誤検知に対処したら、`SecRuleEngine` を `On` にします。
