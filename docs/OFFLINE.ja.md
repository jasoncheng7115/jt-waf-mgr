# オフライン環境：インストールと更新

[English](OFFLINE.md) · [繁體中文](OFFLINE.zh-TW.md) · **日本語**

jt-waf-mgr は Python 標準ライブラリのみを使い、pip も Docker も不要で、インストールや実行のために外部へ接続しません。
インターネットに接続できないホストには、接続できるコンピューターからファイルを持ち込むだけです。以下、「オンラインの
コンピューター」はインターネットに接続できるコンピューター、「ホスト」はインストール先のサーバーを指します。

## 1. オンラインのコンピューターでファイルを用意する

[GitHub Releases](https://github.com/jasoncheng7115/jt-waf-mgr/releases) から同じバージョンの 4 つのファイルを
ダウンロードします：

- `jt-waf-mgr-<バージョン>.tar.gz`
- `jt-waf-mgr-<バージョン>.tar.gz.sig`
- `jt-waf-mgr-<バージョン>.tar.gz.sha256`
- `release-key.pem`

まずそこで検証します（ホストでも再度検証します）：

```sh
sha256sum -c jt-waf-mgr-<バージョン>.tar.gz.sha256
openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-<バージョン>.tar.gz.sig jt-waf-mgr-<バージョン>.tar.gz
openssl pkey -pubin -in release-key.pem -outform DER | sha256sum
```

最後の行が表示する鍵のフィンガープリントは次のとおりでなければなりません：

```
ae3c8d2c761419d1482c21aa46ae09425f766737c6b5c8b181d8bd42f92049f9
```

## 2. ホストに必要なシステムパッケージ

- Python 3.11 以上：Debian 12 / 13 と Ubuntu 24.04 には標準で入っています。
- nginx、ModSecurity-nginx コネクタ、libmodsecurity 3.0.9 以上：社内の apt ミラーから。ミラーがない場合は、
  **同じリリース** のシステム（使い捨ての VM など）で .deb をダウンロードして持ち込みます：

  ```sh
  # オンラインのコンピューター（ホストと同じ Debian / Ubuntu リリース）
  sudo apt-get install --download-only nginx libnginx-mod-http-modsecurity
  cp /var/cache/apt/archives/*.deb ./debs/
  # ホスト
  sudo dpkg -i ./debs/*.deb
  ```

- OWASP CRS 4：オンラインのコンピューターで [CRS の GitHub releases](https://github.com/coreruleset/coreruleset/releases)
  からリリースと `.asc` をダウンロードし、`gpg --verify` で検証して持ち込み、[ModSecurity インストールガイド](MODSECURITY.ja.md)
  の第 3 節のとおりにインストールします。

## 3. インストール

第 1 節の 4 つのファイルをホストに持ち込み（USB メモリ、社内ファイルサーバーなど）、次を実行します：

```sh
sha256sum -c jt-waf-mgr-<バージョン>.tar.gz.sha256
openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-<バージョン>.tar.gz.sig jt-waf-mgr-<バージョン>.tar.gz
tar xzf jt-waf-mgr-<バージョン>.tar.gz && cd jt-waf-mgr-<バージョン>
sudo ./install.sh                   # すべてのファイルとリリース署名を検証し、鍵を固定（pin）します
sudo jt-waf-mgr check
sudo jt-waf-mgr user add <名前> --role admin
```

## 4. 更新

オンラインのコンピューターで新しいバージョンの 4 つのファイルをダウンロードして持ち込み、次を実行します：

```sh
sha256sum -c jt-waf-mgr-<新バージョン>.tar.gz.sha256
tar xzf jt-waf-mgr-<新バージョン>.tar.gz && cd jt-waf-mgr-<新バージョン>
sudo ./upgrade.sh --check           # 確認のみ：インストール済みのプログラムと固定した鍵で新しいリリースを検証
sudo ./upgrade.sh                   # バックアップ、切り替え、確認。どこかで失敗すれば自動で元に戻します
```

`upgrade.sh` はインストール時に固定した鍵を使うため、改変されたリリースや他者が署名したものは拒否されます。
戻すとき：`sudo ./upgrade.sh --rollback`。

## 5. ネットワークが必要な機能をオフラインで使うには

- **GeoIP**（国、ネットワーク事業者、世界地図）：オンラインのコンピューターで MaxMind アカウントを使い
  `GeoLite2-City.mmdb` と `GeoLite2-ASN.mmdb` をダウンロードし、ホストの `/var/lib/jt-waf-mgr/geoip/`（所有者 `jtwaf`、
  権限 0640）に置きます。設定の GeoIP は有効のまま（既定）で、キーを入力する必要はありません。更新するときは同じ手順を繰り返します。
- **イベント分析（LLM）**：社内ネットワーク上の OpenAI 互換 LLM サーバー（llama.cpp、vLLM、Ollama など）を使うため、
  もともとインターネットは不要です。
- **通知**：社内 SMTP によるメール、社内の Zulip や Nextcloud Talk、社内システム向けの汎用 webhook が使えます。
  Telegram、Teams、Slack、Discord は外部サービスへの接続が必要です。
- **ログサーバー（syslog / SIEM）**：社内のログサーバーへ送ります。
- **CRS の更新**：第 2 節と同じ方法で新しい CRS を持ち込みます。
