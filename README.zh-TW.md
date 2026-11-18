# quality-scan-digest

[English](README.md) | 繁體中文

把多個掃描器重疊的輸出合併成**一份去除重複的 JSON 報告**（可另產 HTML），並帶誠實的涵蓋合約：每個來源都是*已收集*、*不完整*或*未收集*。

這**不是** DefectDojo／完整 AppSec 平台的替代品。它對你已有的（或以 digest 鎖定的）工具做固定解析、合併重複通報，並在掃描不完整時拒絕看起來「乾淨」。這裡的 Trivy 只跑 **`trivy config`**（Dockerfile／Helm）；映像檔 CVE 請用設定了 `image` 的 **Snyk Container**。

| 有涵蓋 | **不會**預設跑 |
|---|---|
| SonarQube、Snyk OSS/Code/IaC／（可選）Container、Trivy config、Semgrep、Dependabot 未結案、OSV lockfile（含 `MAL-`）、zizmor、Gitleaks、ClamAV、GuardDog | 預設的 Trivy `image`/`fs` CVE、上表以外的 SCA、runtime/DAST、工單流程 |

| | 工具 | 掃描內容 | 官方 repository | 授權 |
|---|---|---|---|---|
| <img src="https://github.com/SonarSource.png?size=144" width="72" height="72" alt="SonarQube"> | **SonarQube** | 原始碼：bug、漏洞、code smell、security hotspot、程式規模 | [SonarSource/sonarqube](https://github.com/SonarSource/sonarqube) | LGPL-3.0 |
| <img src="https://github.com/snyk.png?size=144" width="72" height="72" alt="Snyk"> | **Snyk** | 開源套件相依性、Code（SAST）、IaC 與 Container 映像檔 | [snyk/cli](https://github.com/snyk/cli) | Apache-2.0 (CLI) |
| <img src="https://github.com/aquasecurity.png?size=144" width="72" height="72" alt="Trivy"> | **Trivy** | Dockerfile 指令與 Helm chart（`trivy config`） | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 |
| <img src="https://github.com/semgrep.png?size=144" width="72" height="72" alt="Semgrep"> | **Semgrep** | Code（SAST）；有 Semgrep token 時另含 Supply Chain 漏洞通報 | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 |
| <img src="https://github.com/dependabot.png?size=144" width="72" height="72" alt="Dependabot"> | **Dependabot** | GitHub 上尚未處理的相依套件警示 | [dependabot/dependabot-core](https://github.com/dependabot/dependabot-core) | MIT (core) |
| <img src="https://github.com/google.png?size=144" width="72" height="72" alt="OSV-Scanner"> | **OSV-Scanner** | 以 OSV 資料庫（含 OpenSSF 惡意套件清單 `MAL-`）比對各生態系的 lockfile | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 |
| <img src="https://github.com/zizmorcore.png?size=144" width="72" height="72" alt="zizmor"> | **zizmor** | GitHub Actions workflow 安全稽核：template injection、權限過大、未固定版本的 action、checkout 留下的憑證 | [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor) | MIT |
| <img src="https://github.com/gitleaks.png?size=144" width="72" height="72" alt="Gitleaks"> | **Gitleaks** | git 歷史中任何一次 commit 進去的機密（不是 repository 時則掃檔案） | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT |
| <img src="https://github.com/Cisco-Talos.png?size=144" width="72" height="72" alt="ClamAV"> | **ClamAV** | checkout 內的已知惡意程式（特徵碼比對） | [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav) | GPL-2.0 |
| <img src="https://github.com/DataDog.png?size=144" width="72" height="72" alt="GuardDog"> | **GuardDog** | 相依套件清單中惡意或有風險的 PyPI / npm / Go 套件 | [DataDog/guarddog](https://github.com/DataDog/guarddog) | Apache-2.0 |

圖示為各維護組織的 GitHub 頭像，商標屬於各自的擁有者。Snyk 與 Dependabot 的 CLI／核心是開源的，但掃描結果需要各自的帳號或 GitHub repository。

測試覆蓋率（Cobertura XML 或 Istanbul `coverage-summary.json`）可以一併放進報告。

需要 Python 3.10 以上，只用標準函式庫。不需要常駐伺服器：SonarQube 以一次性 container 執行，在同一次掃描裡啟動、掃描、匯出，最後刪除。

## 為什麼需要它

**工具之間會重疊。** Snyk、Semgrep Supply Chain、OSV-Scanner、Trivy 和 Dependabot 讀的是同一批漏洞資料庫，同一個有漏洞的套件可能出現四、五次，報告上的每個數字都會被灌水。`qsd` 讓每個問題只列一次，記下有哪些工具看到它，其他工具的回報也完整保留。

**沒掃完就要看得出沒掃完。** 每個來源都會標成*已收集*、*不完整*（附上缺了什麼）或*未收集*（附上原因）。工具沒安裝、沒登入、執行失敗，或輸出的是錯誤訊息而不是結果，都絕不會被當成「掃描乾淨」。**預設就是 `--strict`**（必要來源有缺口則結束碼 `2`）；本機探索不完整結果時才用 `--lenient`。`--tools` 沒選到的工具仍會出現在 `sources`（標成 `optional`），截圖無法假裝「只掃了這些」。

## 安裝

```bash
pip install git+https://github.com/CloudBater/quality-scan-digest@v0.4.1
qsd --version
```

需要哪些掃描工具就裝哪些；每一個都是選用的，沒裝的會在報告中標示出來：
`docker`（SonarQube；沒有 `clamscan` 時 ClamAV 也用它）、
[`snyk`](https://docs.snyk.io/snyk-cli)、[`trivy`](https://trivy.dev)、
[`semgrep`](https://semgrep.dev/docs/getting-started/)、[`gh`](https://cli.github.com)（Dependabot）、
[`gitleaks`](https://github.com/gitleaks/gitleaks)、[`osv-scanner`](https://github.com/google/osv-scanner)、[`zizmor`](https://github.com/zizmorcore/zizmor)（這三個沒裝時改用 `docker`）、
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
| `osv_offline` | `true` 時 OSV-Scanner 下載離線資料庫比對，不查詢 osv.dev（需原生 CLI） |
| `gitleaks_mode` | `git`（掃完整歷史；在 repository 內的預設值）或 `dir`（只掃檔案） |
| `gitleaks_log_opts` | 限縮掃描的歷史範圍，例如 `origin/main..HEAD` |
| `guarddog` | 清單，例如 `{"ecosystem": "pypi" \| "npm" \| "go" \| "github_action", "manifest": "requirements.txt"}` |
| `coverage` | 覆蓋率檔案：checkout 內相對路徑，或 CI artifact 的絕對路徑（只解析） |
| `sonar_args` | 額外的 `-Dsonar.<鍵>=…` 分析參數，只接受**精確白名單**：`sources`、`tests`、各種 `exclusions`／`inclusions`、`sourceEncoding`、`projectName`、報告路徑（如 `sonar.python.coverage.reportPaths`）、`sonar.python.version` 與少數 Java 路徑。其他語言設定（例如 `sonar.typescript.tsconfigPaths`），以及任何會改 scanner、host、token 或可執行檔的鍵，一律拒絕 |
| `semgrep_mode` | `auto`（預設）、`ci`（必須有 token，絕不退回公開規則）、或 `public` |
| `semgrep_partial_is_gap` | 預設 `false`：Semgrep 只能部分解析的檔案算醒目標示的**部分掃描（PARTIAL SCAN）**：來源仍算完整，`sources.*.partial` 記錄檔案數，終端機與 HTML 都會明講。`true` 則算缺口（`incomplete`，strict 結束代碼 2）。Semgrep 的嚴重錯誤一律算不完整 |
| `semgrep_branch` | 每個專案：`semgrep ci` 把這次掃描歸到哪個分支名稱（`SEMGREP_BRANCH`） |

最上層可設定 `snyk_severity`（預設 `high`）和 `trivy_severity`（預設 `CRITICAL,HIGH`）。這些門檻會記錄在報告的 `settings` 裡，因為「門檻以上沒有發現」和「完全沒有發現」是兩回事。

環境變數：設定 `SEMGREP_APP_TOKEN` 時，Semgrep 改用 `semgrep ci` 套用你組織的政策（一律完整掃描，不會只掃差異）。`QSD_SONAR_PORT`、`QSD_SCANNER_IMAGE`、`QSD_CLAMAV_IMAGE`、`QSD_GITLEAKS_IMAGE`、`QSD_OSV_IMAGE`、`QSD_ZIZMOR_IMAGE` 可覆寫預設值。Snyk 和 `gh` 使用它們自己的登入狀態。

### 2. 彙整已經有的掃描結果（CI）

如果你的 pipeline 已經跑過這些工具，用 manifest 指向它們的輸出即可：

```bash
qsd digest manifest.json --json-out report.json --html-out report.html
# 本機 digests 允許不完整時：
qsd digest manifest.json --json-out report.json --lenient
```

範例見 [`examples/manifest.example.json`](examples/manifest.example.json)。若你已自行產出，這裡也接受 Trivy 漏洞輸出（`trivy fs|image --format json`）；`qsd scan` 本身仍只跑 **config**。

SonarQube 可以從匯出的 API 回應（`issues`、`hotspots`、`measures`）讀取，也可以設定 `SONAR_TOKEN` 後，從 `{"host": "...", "project_key": "..."}` 即時讀取。token 只會送往 `https://` 主機，或本機 loopback 上的 HTTP；不會跟隨轉址，也絕不會從 manifest 讀取 token。請使用 user token：analysis token 讀不到 hotspot，報告會標成不完整。

結束代碼：**沒有任何**來源被收集或輸入無效時為 `1`；**預設**在任何必要來源不完整時為 `2`（`--lenient` / `--no-strict` 才放行；同時給 `--strict --lenient` 會報錯）。

**部分掃描（partial）不等於不完整（incomplete）。** 有些工具只能部分掃描某些檔案；例如 Semgrep 在一般的 Django 或 Next.js repository 上，每次都會回報數十個「檔案只能部分解析」的警告。這不會讓來源變成*不完整*（會讓 strict 失敗的缺口），否則每次都會失敗；但它也不是完整掃描，所以來源會帶 `partial`（檔案數），所有輸出都會標明 **PARTIAL SCAN**：終端機的 `!!` 區塊、HTML 的橫幅與琥珀色標籤，而且「Security crit + high」方塊絕不會顯示成綠色。對這些檔案而言，低數字或零，證據力比其他地方弱。設 `semgrep_partial_is_gap: true` 可讓它讓 strict 失敗。

來源只有在專案的 `skipped` 清單裡列出時才算「選用」（`qsd scan` 會為 `--tools` 沒選的工具、以及沒設定 `guarddog` 清單的 GuardDog 寫入這份清單）。備註文字寫了什麼，都不會讓來源變成選用。手寫 manifest 時，請把你刻意沒跑的列在 `"skipped": ["Semgrep", ...]`；其他缺少的來源都會讓 strict 失敗。

Dependabot 以 `open,dismissed,auto_dismissed` 抓取：被 dismiss 的警示計入 `suppressed`。`fixed` 警示不會抓（那是整段歷史），所以 `qsd scan` 的 `dependabot.fixed` 一律是 0。

## 去除重複

**`advisory` 的已知限制：** 它依套件與通報編號比對，不看安裝的版本或 manifest。如果兩個 manifest 安裝了同一個套件的不同版本，而且同一則通報都影響它們，並且兩個掃描器各回報其中一個，這兩筆會合併成一列；另一個出現處會完整保留在 `also`（含位置），但計數只算一個發現。需要「每個出現處各一列」時，請用 `--dedup exact`。

每一輪都刻意保守：合併錯了會把問題藏起來，漏合併只是多算幾筆。

| 規則 | 預設 | 合併條件 |
|---|---|---|
| `exact` | 開 | 同專案、同工具、同類型、同規則、同位置、同行號、**同欄位**、同訊息 |
| `advisory` | 開 | 同專案、同套件（依生態系的命名規則比對），且有共同的 CVE/GHSA 編號，且來自**不同**掃描器。沒有套件名稱的資料，只有在它所有編號都指向同一個套件時才會併入 |
| `sast` | **關** | 同專案、同檔案、同行號、同 CWE，且由**不同**工具回報；每筆資料最多加入一組，不會串連合併 |

合併後保留資訊最完整的那筆，嚴重度取整組中**最嚴重**的，其他工具的回報（訊息、嚴重度、規則、位置、修正建議）完整放在 `also` 底下。`by` 列出所有看到它的工具。不同專案之間絕不合併；Snyk IaC 和 Trivy 的規則編號彼此無關，所以設定錯誤類的問題不會合併。可用 `--dedup exact,advisory,sast` 選擇規則，或用 `--dedup none` 關閉。解析器本身會保留每個受影響的版本與 manifest。

## 豁免檔（`.qsdignore`）

大型掃描的結果多半不需要處理：把稽核紀錄的句子誤判成 SQL 的規則、加固建議、已經開了工單的漏洞。豁免檔可以把它們「放到一邊」，但不會藏起來。請明確指定檔案（`--ignore-file 路徑`，或設定檔的 `"ignore_file"`），範例見 [`examples/qsdignore.example`](examples/qsdignore.example)。

```
ignore src=Semgrep ref="python.django.security.injection.tainted-sql-string.*" loc="app/audit/**" expect=16 until=2027-05-01 reason="稽核紀錄文字，不是 SQL"
track  ref=GHSA-xxxx-xxxx-xxxx loc="*: example-package@1.2.3" ticket=PROJ-123 until=2027-02-01 reason="已排入下一版升級"
```

| 動詞 | 意思 | 是否計入頭條數字 |
|---|---|---|
| `ignore` | 誤判，或已接受的風險 | 否，列在「Waived」區 |
| `track` | 真的問題，但已有工單 | 是，並標上工單號 |

報告多了一個最重要的數字 `untracked_crit_high`：沒有豁免也沒有工單的 CRITICAL／HIGH 資安問題。

- **被豁免的問題不會消失。** 它仍在 `findings` 裡，附上 `waiver`（`status`、`reason`、`ticket`、`until`、`line`）。
- **每一行都要有 `reason` 與 `until` 日期**，最多 12 個月後。過期後問題重新計入，strict 模式會以 exit 2 失敗。
- **HIGH 以上需要 `ticket`**，所有 `track` 也一樣。
- **`expect=N`**：這一行若匹配超過 N 筆，就一筆也不豁免，strict 模式以 exit 2 失敗，避免「忽略這條規則」日後悄悄蓋住新的真問題。
- **機密與惡意程式**只能逐筆用 `track=<該問題的 track>` 豁免，不能用規則樣式。這包括合併了其他掃描器回報的列，以及規則或訊息看起來像機密（secret、password、token、API key、credential、private key、hard-coded）的問題，不論該掃描器把它歸為哪一類。`src=` 只有在沒有其他掃描器也看到同一列時才會豁免它。
- **過時的行**（沒匹配到任何東西）列在 `waivers.stale`；檔案的 SHA-256 會記錄在報告裡。
- 比對條件：`src`、`ref`（規則或通報編號）、`loc`（路徑或 `package@version`）、`project`（專案名稱）、以及精確的 `track`。在 `ref` 與 `loc` 裡，`*` 與 `?` 只在同一層路徑內比對，`**` 可跨越 `/`，其他字元（包含 `[`）都是字面意思。不用行號，因為行號會漂移。`until` 是 UTC 日期，當天仍有效。
- **檔案絕不會從被掃描的 checkout 讀取**，`ignore_file` 放在 checkout 內會被拒絕；否則 pull request 可以替自己的問題開豁免。請放在擁有掃描設定、由資安負責人審核的 repo。

它不取代各工具自己的抑制功能（那些計入 `sources.*.suppressed`）。

## 輸出格式

[`schema/report.schema.json`](schema/report.schema.json) 定義了輸出內容：

```jsonc
{
  "schema_version": "1.2",
  "generator": { "name": "quality-scan-digest", "version": "0.5.0" },
  "title": "…", "version": "v1.4.0", "generated_at": "…",
  "settings": { "snyk_severity": "high", "trivy_severity": "CRITICAL,HIGH", "dedup": "exact,advisory",
                "tools": "…", "images": {…}, "runners": { "clamav": "container" } },
  "generated_from": [ { "project_id": "api", "project": "API", "repo": "…", "commit": "…",
                        "commit_dirty": false, "sonar": {…}, "coverage": {…}, "dependabot": {…},
                        "findings": 120, "security": 40, "sec_crit_high": 3, "sec_unrated": 1,
                        "malware": 2, "waived": 5, "tracked": 1, "untracked_crit_high": 2,
                        "by_source": {…} } ],
  "sources": { "API: Semgrep": { "collected": true, "complete": true,
                                 "note": "PARTIAL SCAN: 88 file(s) only partly parsed, so Semgrep did not fully scan them (the rest of the repository was scanned)", "suppressed": 0, "partial": 88, "optional": false } },
  "waivers": { "file": ".qsdignore", "sha256": "…", "lines": […], "stale": [], "expired": [], "errors": [] },
  "dedup":   { "input": 180, "passes": ["exact", "advisory"], "exact": 4, "advisory": 56, "output": 120 },
  "findings": [ { "id": "…", "track": "…", "project_id": "api", "proj": "API", "src": "Snyk",
                  "by": ["Snyk", "Dependabot"], "kind": "Dependency", "security": true,
                  "sev": "HIGH", "rank": 1, "msg": "…", "loc": "poetry.lock: django@4.2.0",
                  "line": "", "col": "", "ref": "SNYK-…", "ids": ["CVE-…"], "cwe": ["CWE-89"],
                  "fix": "upgrade to …", "also": [ { "src": "Dependabot", "sev": "MEDIUM", "msg": "…" } ],
                  "waiver": null } ]
}
```

各工具的嚴重度統一對應到同一個等級（`rank` 0 = CRITICAL/BLOCKER … 4 = INFO，5 = 未評級 `—`）。`security` 依問題的性質判斷（相依套件、container、IaC、設定錯誤、漏洞、hotspot、機密、workflow、惡意程式、套件風險），不看是哪個工具回報的。趨勢請用 **`track`**：它在同一份報告內唯一，且不含訊息，所以工具改寫標題不會讓它改變。規則與位置相同的列（例如同一行有兩個機密）會用訊息的雜湊區分，這些列的 `track` 只能盡力維持穩定：同組的另一筆消失，或訊息被改寫時，它可能會變。**`id`** 是顯示用雜湊（包含訊息，工具有回報時也包含欄位）。被豁免的問題在工具有提供時計入 `sources.*.suppressed`：Snyk Code SARIF suppressions、zizmor `ignored`、Dependabot dismissed／auto_dismissed、以及 SonarQube 中狀態為 ACCEPTED 或 FALSE_POSITIVE 的 issues（不含已修復的）。`qsd scan` 也會匯出 SonarQube 的豁免數量，所以拿它的原始輸出做 digest 也看得到。Snyk OSS／IaC／Container JSON 不含豁免資訊，因此不會假裝算過；讀不到 SonarQube 豁免數量時，來源會寫「waived-issue count unavailable」，而不是 0。SonarQube 豁免數量需要 10.4 以上的伺服器（較舊的伺服器可能忽略 `issueStatuses`，數字會偏高）。

## 安全注意事項

- 原始輸出、紀錄和產生的報告，可能含有被掃描 repository 的程式碼與機密，請不要當成公開的 CI artifact 上傳。
- 一次性 SonarQube 只綁定在 `127.0.0.1` 的隨機 port 上，只用官方文件寫明的首次開機 `admin` 帳號產生 token，接著立刻更換該密碼。每次執行都使用自己的 compose project，結束時連同 volume 一起刪除。
- scanner、ClamAV、Gitleaks、OSV-Scanner 與 zizmor 映像檔以 digest 固定版本；GitHub Actions 以 commit SHA 固定版本。
- Gitleaks 使用免費的 MIT CLI，不需要授權金鑰（只有 `gitleaks-action` 在組織 repository 上才需要）。它一律以 `--redact` 執行，`qsd` 只保留規則、檔案、行號與 commit：絕不保留機密本身，也不保留 commit 作者、email 或訊息。你 repository 裡的 `.gitleaks.toml` 與 `.gitleaksignore` 會照常生效。在歷史中找到的機密必須撤銷；只從程式碼刪掉並不能挽回外洩。
- OSV-Scanner 預設會把套件名稱與版本（不含程式碼）送到 osv.dev 查詢；設定 `osv_offline` 可改用離線資料庫。zizmor 一律以 `--offline` 執行，不需要 GitHub token，也不會有任何資料離開本機。
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
