# quality-scan-digest

[English](README.md) | 繁體中文

對你的 repository 執行八種程式碼、供應鏈、機密外洩與惡意程式掃描工具，把結果合併成**一份去除重複的清單**，並輸出成 **JSON**（也可以另外產生一份獨立的 HTML 報告）。

| | 工具 | 掃描內容 | 官方 repository | 授權 |
|---|---|---|---|---|
| <img src="https://github.com/SonarSource.png?size=144" width="72" height="72" alt="SonarQube"> | **SonarQube** | 原始碼：bug、漏洞、code smell、security hotspot、程式規模 | [SonarSource/sonarqube](https://github.com/SonarSource/sonarqube) | LGPL-3.0 |
| <img src="https://github.com/snyk.png?size=144" width="72" height="72" alt="Snyk"> | **Snyk** | 開源套件相依性、Code（SAST）、IaC 與 Container 映像檔 | [snyk/cli](https://github.com/snyk/cli) | Apache-2.0 (CLI) |
| <img src="https://github.com/aquasecurity.png?size=144" width="72" height="72" alt="Trivy"> | **Trivy** | Dockerfile 指令與 Helm chart（`trivy config`） | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 |
| <img src="https://github.com/semgrep.png?size=144" width="72" height="72" alt="Semgrep"> | **Semgrep** | Code（SAST）；有 Semgrep token 時另含 Supply Chain 漏洞通報 | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 |
| <img src="https://github.com/dependabot.png?size=144" width="72" height="72" alt="Dependabot"> | **Dependabot** | GitHub 上尚未處理的相依套件警示 | [dependabot/dependabot-core](https://github.com/dependabot/dependabot-core) | MIT (core) |
| <img src="https://github.com/gitleaks.png?size=144" width="72" height="72" alt="Gitleaks"> | **Gitleaks** | git 歷史中任何一次 commit 進去的機密（不是 repository 時則掃檔案） | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT |
| <img src="https://github.com/Cisco-Talos.png?size=144" width="72" height="72" alt="ClamAV"> | **ClamAV** | checkout 內的已知惡意程式（特徵碼比對） | [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav) | GPL-2.0 |
| <img src="https://github.com/DataDog.png?size=144" width="72" height="72" alt="GuardDog"> | **GuardDog** | 相依套件清單中惡意或有風險的 PyPI / npm / Go 套件 | [DataDog/guarddog](https://github.com/DataDog/guarddog) | Apache-2.0 |

圖示為各維護組織的 GitHub 頭像，商標屬於各自的擁有者。Snyk 與 Dependabot 的 CLI／核心是開源的，但掃描結果需要各自的帳號或 GitHub repository。

測試覆蓋率（Cobertura XML 或 Istanbul `coverage-summary.json`）可以一併放進報告。

需要 Python 3.10 以上，只用標準函式庫。不需要常駐伺服器：SonarQube 以一次性 container 執行，在同一次掃描裡啟動、掃描、匯出，最後刪除。

## 為什麼需要它

**工具之間會重疊。** Snyk、Semgrep Supply Chain、Trivy 和 Dependabot 讀的是同一批漏洞資料庫，同一個有漏洞的套件可能出現三、四次，報告上的每個數字都會被灌水。`qsd` 讓每個問題只列一次，記下有哪些工具看到它，其他工具的回報也完整保留。

**沒掃完就要看得出沒掃完。** 每個來源都會標成*已收集*、*不完整*（附上缺了什麼）或*未收集*（附上原因）。工具沒安裝、沒登入、執行失敗，或輸出的是錯誤訊息而不是結果，都絕不會被當成「掃描乾淨」。加上 `--strict`，任何缺口都會讓程式以失敗結束。

## 安裝

```bash
pip install git+https://github.com/CloudBater/quality-scan-digest@v0.2.0
qsd --version
```

需要哪些掃描工具就裝哪些；每一個都是選用的，沒裝的會在報告中標示出來：
`docker`（SonarQube；沒有 `clamscan` 時 ClamAV 也用它）、
[`snyk`](https://docs.snyk.io/snyk-cli)、[`trivy`](https://trivy.dev)、
[`semgrep`](https://semgrep.dev/docs/getting-started/)、[`gh`](https://cli.github.com)（Dependabot）、
[`gitleaks`](https://github.com/gitleaks/gitleaks)（或用 `docker`）、
有最新特徵碼資料庫的 [`clamscan`](https://docs.clamav.net)（`freshclam`）、
[`guarddog`](https://github.com/DataDog/guarddog)，以及要掃 chart 時的 `helm`。

## 使用方式

### 1. 一次完成掃描與彙整

```bash
qsd scan examples/qsd.example.json --release v1.4.0 --out-dir qsd-out
```

每次執行都會建立一個全新、僅限本人存取（`0700`）的目錄 `qsd-out/run-<時間>-<id>/`，內含 `report.json`、`report.html`、`manifest.json`、`raw/` 底下各工具的原始輸出，以及 `logs/` 底下各工具的紀錄。**請把這個目錄當成機密**：原始輸出和紀錄裡有程式碼片段，以及關於你系統的掃描結果。

用 `--tools snyk,trivy,clamav` 可以只跑部分工具。設定檔中的路徑以設定檔所在位置為基準，且不能指到專案外面。範例見 [`examples/qsd.example.json`](examples/qsd.example.json)：

| 欄位 | 說明 |
|---|---|
| `name` | 專案 id：英文字母、數字、`.`、`_`、`-`；不可重複 |
| `label` | 顯示名稱；不可重複 |
| `path` | 要掃描的本機 checkout。請掃 release 對應的版本，不要掃正在改的工作目錄 |
| `repo` | GitHub 上的 `owner/name`，給 Dependabot 用 |
| `sonar_project_key` | 預設為 `name` |
| `snyk_open_source_args` | 預設為 `--all-projects --fail-fast` |
| `image` | 給 Snyk Container 掃的映像檔。請固定成實際出貨版本的 **digest**，不要用會變動的 tag |
| `helm.chart`、`helm.values`、`helm.extra_manifests` | 掃 IaC 前先 render 到暫存目錄（用完即刪）；Snyk 無法直接讀 Helm 範本 |
| `semgrep_config` | 沒設定 `SEMGREP_APP_TOKEN` 時使用的規則集（預設 `p/default`） |
| `gitleaks_mode` | `git`（掃完整歷史；在 repository 內的預設值）或 `dir`（只掃檔案） |
| `gitleaks_log_opts` | 限縮掃描的歷史範圍，例如 `origin/main..HEAD` |
| `guarddog` | 清單，例如 `{"ecosystem": "pypi" \| "npm" \| "go" \| "github_action", "manifest": "requirements.txt"}` |
| `coverage` | checkout 內的覆蓋率檔案 |

最上層可設定 `snyk_severity`（預設 `high`）和 `trivy_severity`（預設 `CRITICAL,HIGH`）。這些門檻會記錄在報告的 `settings` 裡，因為「門檻以上沒有發現」和「完全沒有發現」是兩回事。

環境變數：設定 `SEMGREP_APP_TOKEN` 時，Semgrep 改用 `semgrep ci` 套用你組織的政策（一律完整掃描，不會只掃差異）。`QSD_SONAR_PORT`、`QSD_SCANNER_IMAGE`、`QSD_CLAMAV_IMAGE`、`QSD_GITLEAKS_IMAGE` 可覆寫預設值。Snyk 和 `gh` 使用它們自己的登入狀態。

### 2. 彙整已經有的掃描結果（CI）

如果你的 pipeline 已經跑過這些工具，用 manifest 指向它們的輸出即可：

```bash
qsd digest manifest.json --json-out report.json --html-out report.html --strict
```

範例見 [`examples/manifest.example.json`](examples/manifest.example.json)。這裡也接受 Trivy 的漏洞輸出（`trivy fs|image --format json`）。

SonarQube 可以從匯出的 API 回應（`issues`、`hotspots`、`measures`）讀取，也可以設定 `SONAR_TOKEN` 後，從 `{"host": "...", "project_key": "..."}` 即時讀取。token 只會送往 `https://` 主機，或本機 loopback 上的 HTTP；不會跟隨轉址，也絕不會從 manifest 讀取 token。請使用 user token：analysis token 讀不到 hotspot，報告會標成不完整。

結束代碼：**沒有任何**來源被收集或輸入無效時為 `1`；加上 `--strict` 時，任何列出的來源沒有完整收集則為 `2`。

## 去除重複

每一輪都刻意保守：合併錯了會把問題藏起來，漏合併只是多算幾筆。

| 規則 | 預設 | 合併條件 |
|---|---|---|
| `exact` | 開 | 同專案、同工具、同類型、同規則、同位置、同行號、同訊息 |
| `advisory` | 開 | 同專案、同套件（依生態系的命名規則比對），且有共同的 CVE/GHSA 編號。沒有套件名稱的資料，只有在它所有編號都指向同一個套件時才會併入 |
| `sast` | **關** | 同專案、同檔案、同行號、同 CWE，且由**不同**工具回報；每筆資料最多加入一組，不會串連合併 |

合併後保留資訊最完整的那筆，嚴重度取整組中**最嚴重**的，其他工具的回報（訊息、嚴重度、規則、位置、修正建議）完整放在 `also` 底下。`by` 列出所有看到它的工具。不同專案之間絕不合併；Snyk IaC 和 Trivy 的規則編號彼此無關，所以設定錯誤類的問題不會合併。可用 `--dedup exact,advisory,sast` 選擇規則，或用 `--dedup none` 關閉。解析器本身會保留每個受影響的版本與 manifest。

## 輸出格式

[`schema/report.schema.json`](schema/report.schema.json) 定義了輸出內容：

```jsonc
{
  "schema_version": "1.0",
  "title": "…", "version": "v1.4.0", "generated_at": "…",
  "settings": { "snyk_severity": "high", "trivy_severity": "CRITICAL,HIGH", "dedup": "exact,advisory" },
  "generated_from": [ { "project_id": "api", "project": "API", "repo": "…", "commit": "…",
                        "sonar": {…}, "coverage": {…}, "dependabot": {…},
                        "findings": 120, "security": 40, "sec_crit_high": 3, "by_source": {…} } ],
  "sources": { "API: Semgrep": { "collected": true, "complete": false, "note": "incomplete: 2 scan error(s)" } },
  "dedup":   { "input": 180, "passes": ["exact", "advisory"], "exact": 4, "advisory": 56, "output": 120 },
  "findings": [ { "id": "…", "project_id": "api", "proj": "API", "src": "Snyk",
                  "by": ["Snyk", "Dependabot"], "kind": "Dependency", "security": true,
                  "sev": "HIGH", "rank": 1, "msg": "…", "loc": "poetry.lock: django@4.2.0",
                  "line": "", "ref": "SNYK-…", "ids": ["CVE-…"], "cwe": ["CWE-89"],
                  "fix": "upgrade to …", "also": [ { "src": "Dependabot", "sev": "MEDIUM", "msg": "…" } ] } ]
}
```

各工具的嚴重度統一對應到同一個等級（`rank` 0 = CRITICAL/BLOCKER … 4 = INFO）。`security` 依問題的性質判斷（相依套件、container、IaC、設定錯誤、漏洞、hotspot、機密、惡意程式、套件風險），不看是哪個工具回報的。`id` 是內容雜湊，在同一份報告中不會重複；訊息、位置或行號改變時它也會跟著改變。

## 安全注意事項

- 原始輸出、紀錄和產生的報告，可能含有被掃描 repository 的程式碼與機密，請不要當成公開的 CI artifact 上傳。
- 一次性 SonarQube 只綁定在 `127.0.0.1` 的隨機 port 上，只用官方文件寫明的首次開機 `admin` 帳號產生 token，接著立刻更換該密碼。每次執行都使用自己的 compose project，結束時連同 volume 一起刪除。
- scanner、ClamAV 與 Gitleaks 映像檔以 digest 固定版本；GitHub Actions 以 commit SHA 固定版本。
- Gitleaks 使用免費的 MIT CLI，不需要授權金鑰（只有 `gitleaks-action` 在組織 repository 上才需要）。它一律以 `--redact` 執行，`qsd` 只保留規則、檔案、行號與 commit：絕不保留機密本身，也不保留 commit 作者、email 或訊息。你 repository 裡的 `.gitleaks.toml` 與 `.gitleaksignore` 會照常生效。在歷史中找到的機密必須撤銷；只從程式碼刪掉並不能挽回外洩。
- 在 Linux 上，SonarQube 需要主機的 `vm.max_map_count >= 524288`。
- GuardDog 會從套件庫下載每個相依套件來分析（不會安裝或執行）。`capability-*` 規則只代表套件*能*做什麼，標為 LOW；`threat-*` 規則標為 HIGH。
- 如果發現本工具的漏洞，請私下回報，見 [SECURITY.md](SECURITY.md)。

## 開發

```bash
python3 -m unittest discover -s tests -v
```

請參考 [CONTRIBUTING.md](CONTRIBUTING.md) 與 [CHANGELOG](CHANGELOG.md)。

## 授權

[MIT](LICENSE)
