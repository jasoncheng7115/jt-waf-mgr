# リリースチェックリスト

[English](TEST_CHECKLIST.md) · [繁體中文](TEST_CHECKLIST_zh-TW.md) · **日本語**

すべてのリリースは、どこか（サイト、テスト機、顧客）に公開またはインストールする前に、以下のすべてに合格しなければなりません。
一項目でも不合格ならリリースを止めます。「小さな変更だから」は例外になりません。各ゲートの対象と合格条件は `TEST_PLAN.md`
を参照してください。

## 1. コード
- [ ] `python3 -m unittest discover -s tests -t .` — すべて合格（`tools/make_release.sh` でも実行）。
- [ ] `tools/build_frontend.sh` — ビルド、`check_i18n`（3 言語、全角スラッシュなし）、`check_ui`
      （ボタンにアイコン、ネイティブの select / 日付入力なし、表は DataTable 経由）がすべて OK。
- [ ] `python3 tools/preflight.py` — 公開チェック（非公開の名前、アドレス、秘密情報）が OK。README.md /
      README_zh-TW.md / README_ja.md のタイトルに新しいバージョンがあることも確認します（それらと docs/index.html を更新）。
- [ ] UI が変わった場合は、README のスクリーンショットをブラウザテストから更新（`docs/shots/{en,zh-TW,ja}/`）。

## 2. ブラウザ
- [ ] `tools/e2e/run.sh` — 全ページを zh-TW と en、ライトとダークで、テーマ切り替え、並べ替え / 絞り込み / 列の選択 /
      ページ送り、セレクトボックスと日付ピッカー、ツールチップ付きのグラフ、ガイド、ログインページと favicon。
      コンソールエラーなし、生の i18n キーなし、アイコンのないボタンなし。
- [ ] 同じ実行の最後に `tools/security_scan.py`：`security scan: OK`（ヘッダー、cookie、全ルートの認証と認可、CSRF、
      メソッド、トラバーサル、悪意ある入力、不正な形式の本文、ログイン）。
- [ ] UI 変更時：スクリーンショットを確認します。スマートフォン幅（375 px）とタブレット（768 px）を含みます。
- [ ] `tools/zap_scan.py` — 使い捨てのログイン済みインスタンスに OWASP ZAP（パッシブ + アクティブ）：検出 URL ≥ 40、
      かつ `deploy/zap-baseline.conf` 以外の High / Medium / Low の警告なし。レポートを保管（`zap-reports/`）。

## 3. インストールとアップグレード
- [ ] `tools/make_release.sh` — 署名済みリリース。`openssl dgst -sha256 -verify deploy/release-key.pem
      -signature dist/jt-waf-mgr-X.Y.Z.tar.gz.sig dist/jt-waf-mgr-X.Y.Z.tar.gz` が Verified OK を返すこと。
- [ ] `tools/test_upgrade.sh dist/<previous>.tar.gz dist/<new>.tar.gz` — データ付きで前のリリースをインストール、
      拒否、`--check`、起動失敗時の自動ロールバック、アップグレード（データ、アカウント、監査記録、完全性）、
      手動ロールバック、再アップグレード。
- [ ] 本番の Python バージョン（サーバー自身の python3）で、一時ディレクトリ内で：単体テストと `tools/test_upgrade.sh`。
      一時ディレクトリの外には一切触れません。
- [ ] 本番データベースのコピーでデータベース移行（コピーを指す設定で `jt-waf-mgr migrate`）、続いてコピーに対して
      `integrity`。

## 4. 実データ
- [ ] 外部データを読む機能は、少なくとも一度は本物でテストします（例：MMDB リーダーには実際の GeoLite2 データベース、
      コレクターには実際の ModSecurity 監査記録）。

## 5. セキュリティ
- [ ] 新しい書き込みルートは監査される（`TestAuditCoverage`）、新しい入力は検証される、攻撃者が制御するテキストは
      テキストとして表示される。適用プログラム、コレクター、認証、完全性への変更は、それを書いていない人（または
      エージェント）がレビューします。

## 6. 本番へのインストール
- [ ] まずサーバー上で `sudo ./upgrade.sh --check`、次に `sudo ./upgrade.sh`。
- [ ] その後：`sudo jt-waf-mgr doctor`、Web インターフェース、（nginx が関わる場合は）サイトの確認。
- [ ] バージョン、時刻、結果をデプロイ記録に残します。
