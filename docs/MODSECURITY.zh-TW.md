# ModSecurity 安裝手冊（nginx + libmodsecurity v3 + OWASP CRS 4）

[English](MODSECURITY.md) · **繁體中文** · [日本語](MODSECURITY.ja.md)

這份手冊從一台只有 nginx（或什麼都還沒有）的主機開始，裝好 jt-waf-mgr 需要的 ModSecurity 環境。已經有 ModSecurity 的
站台不必照做，對照第 6 節最後列出的「jt-waf-mgr 需要的設定」確認即可。

> 先以「只記錄」（`DetectionOnly`）上線，用 jt-waf-mgr 看一段時間的事件、處理誤判，再改成封鎖（`On`）。

## 1. 系統與套件

- Debian 12 / 13：`libnginx-mod-http-modsecurity`，libmodsecurity 3.0.9 以上隨套件安裝。
- Ubuntu 24.04：`libnginx-mod-http-modsecurity`，libmodsecurity 3.0.12（套件名稱 `libmodsecurity3t64`）。
- Ubuntu 22.04：套件的 libmodsecurity 低於 3.0.9，請改用 24.04 或自行編譯。

```sh
sudo apt install nginx libnginx-mod-http-modsecurity
apt-cache policy libmodsecurity3 libmodsecurity3t64   # 確認版本 ≥ 3.0.9
nginx -V 2>&1 | head -1                                # 確認是發行版的 nginx
ls /etc/nginx/modules-enabled/ | grep -i modsecurity    # 模組已載入
```

連接器模組必須跟執行中的 nginx 是同一份建置。如果你用的是 nginx.org 的套件，發行版的模組載入不了：請改用發行版的 nginx，
或以同一版 nginx 原始碼（`./configure --with-compat --add-dynamic-module=ModSecurity-nginx`）編譯動態模組。

發行版的 `modsecurity-crs` 套件是 CRS 3.3，**不要裝**；CRS 4 依第 3 節取得。

## 2. ModSecurity 基本設定

設定放在 `/etc/nginx/modsec/`。`modsecurity.conf-recommended` 與 `unicode.mapping` 取自 ModSecurity 原始碼中**與你的
libmodsecurity 相同版本**的標籤（[github.com/owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)）。

```sh
sudo install -d -m 755 /etc/nginx/modsec
V=3.0.9   # 換成 apt-cache policy 顯示的版本
cd /etc/nginx/modsec
sudo curl -fLo modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/modsecurity.conf-recommended
sudo curl -fLO https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/unicode.mapping
```

在 `modsecurity.conf` 確認或修改這幾行：

```apache
SecRuleEngine DetectionOnly          # 先只記錄；觀察後改 On
SecAuditEngine RelevantOnly
SecAuditLogType Serial
SecAuditLogFormat JSON               # jt-waf-mgr 讀 JSON 格式
SecAuditLog /var/log/modsecurity/modsec_audit.log
```

`SecAuditLogParts` 保留檔案原本的值即可；請求內容裡的敏感欄位（密碼、權杖、Cookie 等）由 jt-waf-mgr 在寫入資料庫前遮蔽。

## 3. OWASP CRS 4

從 [CRS 的 GitHub releases](https://github.com/coreruleset/coreruleset/releases) 下載最新的 4.x 發行檔與對應的 `.asc`
簽章，依 CRS 文件以 `gpg --verify` 驗證後再解開：

```sh
CRS=4.x.y                           # 換成實際版本
cd /etc/nginx/modsec
sudo tar xzf ~/coreruleset-$CRS.tar.gz   # 檔名與解開後的目錄名以 releases 頁面為準
sudo ln -sfn coreruleset-$CRS crs        # 之後升級 CRS 只要換連結
sudo cp crs/crs-setup.conf.example crs-setup.conf
```

> 另一個做法：裝好 jt-waf-mgr 後，在 CRS 頁開啟「由本系統保持 CRS 最新」，等它下載並驗證 CRS 4，再按「在沙箱比對並提出安裝」，
> 核准後由 jt-waf-mgr 安裝、建立 `crs` 連結與 `crs-setup.conf`，並在主設定檔的 `modsecurity.conf` 之後加上 Include。

## 4. 主設定檔與站台規則檔

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

這兩個檔案是站台自己的規則（排除、阻擋），可以先空著。jt-waf-mgr「納管」時會把其中的規則原樣匯入，並讓 `main.conf`
改為載入它管理的檔案；之後的規則變更都經過 jt-waf-mgr 的流程。

在 nginx 的 `http { }`（全部站台）或個別 `server { }` 加上：

```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

## 5. 稽核記錄目錄與輪替

```sh
sudo install -d -m 750 -o root -g adm /var/log/modsecurity
```

`/etc/logrotate.d/modsecurity`（libmodsecurity 在 reload 時不會重開檔案，所以要用 `copytruncate`）：

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

## 6. 測試

```sh
sudo nginx -t && sudo systemctl reload nginx
curl -s -o /dev/null -w '%{http_code}\n' 'http://localhost/?q=<script>alert(1)</script>'
sudo tail -n 1 /var/log/modsecurity/modsec_audit.log | python3 -m json.tool | head -20
```

只記錄模式下回應碼照常（例如 200），稽核記錄會有一筆含 CRS 規則編號的 JSON。

jt-waf-mgr 需要的設定：`SecAuditLogFormat JSON`、`SecAuditEngine` 不是 `Off`、主設定檔載入 CRS 的 `rules/*.conf`、
稽核記錄目錄可由 `adm` 群組讀取。

## 7. 接著安裝 jt-waf-mgr

照 [README](../README_zh-TW.md#安裝) 安裝後執行 `sudo jt-waf-mgr check`：它會列出找到的主設定檔、CRS 版本與規則數，
以及任何不符合上面要求的設定。觀察一段時間、處理誤判之後，再把 `SecRuleEngine` 改成 `On`。
