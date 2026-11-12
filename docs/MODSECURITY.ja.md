# ModSecurity インストールガイド（nginx + libmodsecurity v3 + OWASP CRS 4）

[English](MODSECURITY.md) · [繁體中文](MODSECURITY.zh-TW.md) · **日本語**

nginx だけがある（またはまだ何もない）ホストから、jt-waf-mgr が必要とする ModSecurity 環境を構築する手順です。
すでに ModSecurity を運用しているサイトは、第 6 節の最後にある「jt-waf-mgr に必要な設定」と照らし合わせるだけで構いません。

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

ディストリビューションの `modsecurity-crs` パッケージは CRS 3.3 なので**インストールしないでください**。CRS 4 は第 3 節の手順で入手します。

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

## 3. OWASP CRS 4

[CRS の GitHub releases](https://github.com/coreruleset/coreruleset/releases) から最新の 4.x リリースと対応する `.asc`
署名をダウンロードし、CRS のドキュメントに従って `gpg --verify` で検証してから展開します：

```sh
CRS=4.x.y                                # 実際のバージョン
cd /etc/nginx/modsec
sudo tar xzf ~/coreruleset-$CRS.tar.gz   # ファイル名と展開後のディレクトリ名は releases ページのとおり
sudo ln -sfn coreruleset-$CRS crs        # CRS の更新はリンクを差し替えるだけ
sudo cp crs/crs-setup.conf.example crs-setup.conf
```

## 4. メイン設定ファイルとサイトのルールファイル

`/etc/nginx/modsec/main.conf`：

```apache
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs-setup.conf
Include /etc/nginx/modsec/site-before-crs.conf
Include /etc/nginx/modsec/crs/rules/*.conf
Include /etc/nginx/modsec/site-after-crs.conf
```

```sh
sudo touch /etc/nginx/modsec/site-before-crs.conf /etc/nginx/modsec/site-after-crs.conf
```

この 2 つのファイルはサイト独自のルール（除外、ブロック）用で、最初は空で構いません。jt-waf-mgr で取り込むと、
中のルールをそのまま取り込み、`main.conf` は jt-waf-mgr が管理するファイルを読み込むように変わります。以後のルール変更は
すべて jt-waf-mgr のワークフローを通ります。

nginx の `http { }`（全サイト）または個別の `server { }` に追加します：

```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

## 5. 監査ログのディレクトリとローテーション

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

## 6. テスト

```sh
sudo nginx -t && sudo systemctl reload nginx
curl -s -o /dev/null -w '%{http_code}\n' 'http://localhost/?q=<script>alert(1)</script>'
sudo tail -n 1 /var/log/modsecurity/modsec_audit.log | python3 -m json.tool | head -20
```

検知のみのモードでは応答コードは通常どおり（例えば 200）で、監査ログに CRS のルール番号を含む JSON が 1 件記録されます。

jt-waf-mgr に必要な設定：`SecAuditLogFormat JSON`、`SecAuditEngine` が `Off` でないこと、メイン設定ファイルが CRS の
`rules/*.conf` を読み込むこと、監査ログのディレクトリを `adm` グループが読めること。

## 7. 続いて jt-waf-mgr をインストール

[README](../README_ja.md#インストール) のとおりにインストールし、`sudo jt-waf-mgr check` を実行します。見つかったメイン
設定ファイル、CRS のバージョンとルール数、上記の要件を満たさない設定が表示されます。しばらく様子を見て誤検知に
対処したら、`SecRuleEngine` を `On` にします。
