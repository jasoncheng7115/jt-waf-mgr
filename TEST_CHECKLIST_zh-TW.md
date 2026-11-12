# 發版檢查清單

[English](TEST_CHECKLIST.md) · **繁體中文** · [日本語](TEST_CHECKLIST_ja.md)

每一次發行在公開或安裝到任何地方（站台、測試機、客戶）之前，都要通過以下所有項目。任何一項失敗就停止發行；
「只是小變更」不是例外。每道關卡涵蓋什麼、怎樣算通過：見 `TEST_PLAN.md`。

## 1. 程式碼
- [ ] `python3 -m unittest discover -s tests -t .` — 全部通過（`tools/make_release.sh` 也會執行）。
- [ ] `tools/build_frontend.sh` — 建置、`check_i18n`（三種語言、沒有全形斜線）與 `check_ui`
      （按鈕有圖示、沒有原生 select / 日期輸入、表格使用 DataTable）全部成功。
- [ ] `python3 tools/preflight.py` — 發佈檢查（私人名稱、位址、機密）成功；它也會檢查
      README.md / README_zh-TW.md / README_ja.md 的標題含新版本號（更新它們以及 docs/index.html）。
- [ ] 介面有變更時，用瀏覽器測試的結果更新 README 截圖（`docs/shots/{en,zh-TW,ja}/`）。

## 2. 瀏覽器
- [ ] `tools/e2e/run.sh` — 每一頁的 zh-TW 與 en、淺色與深色、佈景主題切換、排序 / 篩選 / 欄位選擇 / 分頁、
      下拉選單與日期選擇器、含提示框的圖表、使用說明、登入頁與 favicon；沒有主控台錯誤、沒有未翻譯的 i18n 鍵、
      沒有缺圖示的按鈕。
- [ ] 同一次執行最後跑 `tools/security_scan.py`：`security scan: OK`（標頭、cookie、每個路由的驗證與授權、CSRF、
      方法、路徑穿越、惡意輸入、格式錯誤的內容、登入）。
- [ ] 介面有變更時：檢視截圖，包含手機寬度（375 px）與平板（768 px）。
- [ ] `tools/zap_scan.py` — 對拋棄式已登入實例做 OWASP ZAP（被動 + 主動）掃描：看到的網址 ≥ 40，且沒有
      `deploy/zap-baseline.conf` 以外的 High / Medium / Low 警示。保留報告（`zap-reports/`）。

## 3. 安裝與升級
- [ ] `tools/make_release.sh` — 已簽章的發行檔；`openssl dgst -sha256 -verify deploy/release-key.pem
      -signature dist/jt-waf-mgr-X.Y.Z.tar.gz.sig dist/jt-waf-mgr-X.Y.Z.tar.gz` 顯示 Verified OK。
- [ ] `tools/test_upgrade.sh dist/<previous>.tar.gz dist/<new>.tar.gz` — 含資料安裝上一版、拒絕情況、`--check`、
      啟動失敗時自動還原、升級（資料、帳號、稽核記錄、完整性）、手動還原、再次升級。
- [ ] 在正式機的 Python 版本（伺服器本身的 python3）上、於臨時目錄中執行：單元測試與 `tools/test_upgrade.sh`。
      不動到臨時目錄以外的任何東西。
- [ ] 對正式資料庫的複本做資料庫遷移（`jt-waf-mgr migrate`，設定指向複本），然後對複本執行 `integrity`。

## 4. 真實資料
- [ ] 讀取外部資料的功能至少用真實資料測試一次（例如 MMDB 讀取器用真實的 GeoLite2 資料庫、收集器用真實的
      ModSecurity 稽核記錄）。

## 5. 安全
- [ ] 新的寫入路由有稽核（`TestAuditCoverage`）、新的輸入有驗證、攻擊者可控的文字以文字顯示。套用程式、收集器、
      驗證或完整性的變更，要由沒有撰寫它們的人（或 agent）審查。

## 6. 正式機安裝
- [ ] 先在伺服器上執行 `sudo ./upgrade.sh --check`；再執行 `sudo ./upgrade.sh`。
- [ ] 之後：`sudo jt-waf-mgr doctor`、網頁介面，以及（涉及 nginx 時）站台檢查。
- [ ] 在部署記錄中記下版本、時間與結果。
