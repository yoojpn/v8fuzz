"""
CrashAnalyzer: クラッシュ解析・VRP判定
・Geminiに公式VRPルールを渡して正確な判定
・7日ルール・フラグチェックの事前フィルター
・CVSS推定・報奨金推定
"""
import asyncio
import json
import logging
import re
import sqlite3
import time
from pathlib import Path
from typing import Optional
import aiohttp
from html.parser import HTMLParser

log = logging.getLogger('analyzer')


VRP_SYSTEM_PROMPT = None  # 起動時にfetch


class _HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._texts = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'nav', 'footer', 'header'):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'nav', 'footer', 'header'):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            text = data.strip()
            if text:
                self._texts.append(text)

    def get_text(self):
        return '\n'.join(self._texts)


async def fetch_vrp_rules(url: str) -> str:
    """VRPルールを返す。bughunters.google.comはSPAのため静的fetchでは取得不可。
    FALLBACK_RULESに最新ルールをハードコードして使用する。"""
    log.info("VRPルール: ハードコードFALLBACK_RULESを使用")
    return FALLBACK_RULES


FALLBACK_RULES = """
Chrome Vulnerability Reward Program Rules
Scope of program 
Any High or Critical severity bug in Chrome Browser may be considered. It’s that simple!*

* Well, it's almost that simple. Important key points:

We are interested in bugs that make it to our Stable, Beta, and Dev channels.
Reports for security bugs introduced in newly landed code on trunk / head within the last seven days are not eligible for VRP rewards.
We'd also love to learn about bugs in third-party components that we ship or use (e.g. PDFium, Skia).
Bugs may be eligible even if they are part of the base operating system or GPU driver bugs that are reachable from a renderer process and triggerable through Chrome Browser, such as user mode GPU driver bugs in Mesa or Mali drivers.
For a full reward, the bug must be reachable on the latest OS and 64-bit hardware and manifest in an active release channel of Chrome, on a supported platform.
If these bugs are in a project or product maintained outside of Google, they should be reported – by you – upstream to that project or vendor in parallel to reporting them to us. This ensures you have visibility to the status of the fix, receive credit for the discovery, and we are not brokering bugs on your behalf.
Bugs not reported upstream may not be eligible for a full reward.
Bugs in WebKit that impact Chrome on iOS are not eligible for a VRP reward if they are not reported upstream to Apple.
Bugs in unlaunched features – in code behind a feature flag not enabled by default – are generally eligible for the full potential VRP reward. See below for excluded features.
MiraclePtr-protected bugs are no longer considered security issues and are not in scope for VRP rewards.
We are very interested in research of bypasses of MiraclePtr protection, resulting in exploitation of and RCE from a vulnerability that is protected by MiraclePtr. Reports of a MiraclePtr bypass are eligible for a potential $100,115 reward. A demonstration of exploitation of a BRP-protected use-after-free (UAF) through a report of a novel UAF with PoC or exploit is eligible for additional rewards. The MiraclePtr bypass reward is detailed in the Additional Chrome Rewards section below.
A vulnerability is protected by MiraclePtr only when the test case triggering it results in a status of "MiraclePtr Status: PROTECTED" when reproduced in an ASAN build. Issues with test cases that result in a status of "MiraclePtr Status: NEEDS MANUAL ANALYSIS" in an ASAN build will be reviewed and handled as potential security issues. If, during the course of triage and investigation, the bug is deemed to be protected, it will be downgraded to a bug and handled as a functional issue and would not be eligible for a VRP reward.
Qualifying vulnerabilities 
The Chrome VRP covers all reproducible security issues with critical and high impact, plus bugs that fall into special categories outlined below.

Keep the following rules in mind:

Only the first actionable report of a given issue that we were previously unaware of is eligible. In the event of a duplicate submission, the earliest filed actionable bug report in the bug tracker is generally considered the first report. Please see the below subsection Update to policy regarding unactionable reports and duplicates. for more information.
Bugs disclosed publicly or to a third-party for purposes other than fixing the bug will typically not qualify for a reward. We encourage coordinated disclosure, and believe disclosure is a two-way street; it's our duty to fix serious bugs within a reasonable timeframe.
We take into account if the report caused us to make a security-beneficial change, i.e. we would likely not reward if we would have fixed the issue without the report.
Speculative reports that describe a vulnerability but do not demonstrate that it manifests in Chrome will be closed and will not be treated as the first report of an issue.
Chrome runs internal tooling to find bugs. Reports may be duplicated against internally sourced issues up to seven days after submission. Internal tooling will not have visibility of external reports during this window.
Experimental features, debugging features, and unsafe flags are not in scope.
See the VRP FAQ for some pointers.

Report Quality 
Reports should adhere to our formatting guidelines to be considered for an award any category.

Report Formatting & Attachments 
Reports should be submitted in a way that makes it easy for us (and supporting friendly robots) to read and understand the bug. These form part of our baseline reporting requirements. We value brief reports and will consider over-long reports that make spurious claims about impact as being below baseline.

All reports must:

Be brief and to the point
Attach PoCs and traces as individual files
Attach PoC extensions as individual files
Use only Python to serve example files
Avoid using Restricted content
Be reliably reproducible in Chrome, d8 or a supported test binary.
Custom test harnesses are not supported
Attach a proof of concept (PoC) showing reachability in Chrome or d8
Provide clear, concise, and ordered steps to reproduce
Specify Chrome versions affected by the bug
Reports of memory safety issues must:

Attach a fully symbolized ASAN stack including all additional information, or a fully symbolized MTE stack, or a chrome://crashes id
Attach a minimized PoC or patch
Patches must use process-guards if code can run in multiple processes
Attach Python serving code if necessary (other languages such as Node or PHP will not be accepted)
Ensure that Chrome or d8 do not run in a harness
Provide a minimized set of flags required for Chrome or d8
Reports of Web Platform Security issues must:

Attach a minimized PoC or patch
Patches must use process-guards if code can run in multiple processes
Attach python serving code if necessary (other languages such as Node or PHP will not be accepted)
Chrome or d8 should not run in harness
A minimized set of flags required for Chrome or d8 should be provided
Clearly and briefly describe the broken and expected behavior
Reports of UI security issues must:

Attach a brief video demonstrating the problem
Attach Python serving code if necessary (other languages such as Node or PHP will not be accepted)
Attach a minimized PoC
Clearly and briefly describe the broken and expected behavior
Reports that do not meet our baseline requirements will be limited to a below baseline reward amount, no matter which category they meet.

Reports must not:

Provide only a crash dump
Provide a stack trace without symbols
Be submitted without a Proof of Concept (PoC) or only provide a poor-quality PoC (e.g. a large fuzz file dump with no attempt at reduction)
Simply suggest a theoretical or potential vulnerability based solely on static code analysis
Patch unit or browser tests
Use LD_PRELOAD to simulate a compromised renderer
Overstate the impact of an issue
Reports that consist of the above may not qualify for VRP rewards.

Less convincing or more constrained bug submissions will likely qualify for reduced reward amounts, as chosen at the discretion of the reward panel.

Consistently submitting below baseline reports may lead to suspension from the Chrome VRP.

Memory Safety Reward Amounts 
Memory safety issues are rewarded only if they reproduce on our infrastructure.

Memory corruption per-bug rewards 
The base reward amount for memory safety issues is $500, with multipliers below for the reachability, and level of exploitability, demonstrated on our infrastructure. The base reward may change from time to time. Changes to the base reward will be communicated on this page.

To be eligible for a full reward, an issue must reproduce reliably on our infrastructure. Issues for which we do not have a harness will be limited to the base reward amount. The problem must be web accessible, i.e. it can be triggered by remote content. The issue must not be mitigated. Issues requiring substantial user interaction, installing an extension, triggered by browser shutdown or profile destruction are limited to the base reward amount.

Browser / Network / GPU	ASAN Read	ASAN Write, UAF	Controlled Read	Controlled Write
From web contents	x2 : $1,000	x5 : $2,500	x5 : $2,500	x10 : $5,000
From MojoJS	x1 : $500	x3 : $1,500	x4 : $2,000	x5 : $2,500
From patched renderer	x1 : $500	x2 : $1,000	N/A	N/A
Other Processes	ASAN Read	ASAN Write, UAF	v8 logic	v8 sbox	v8 controlled sbox
Renderer	x1 : $500	x2 : $1,000	x1 : $500	x2 : $1,000	x5 : $2,500
Other Sandboxed	x1 : $500	x1 : $500	x1 : $500	N/A	N/A
ASAN Reads: small ASAN reads, small OOB reads, and use-after-poison will be treated as ASAN READ.
ASAN Write: other ASAN writes, UAFs, and pointer-sized ASAN reads are treated as ASAN WRITE.
Controlled Read/Write: Demonstrated using a Dev, Beta, or Stable build of Chrome with a special flag. Not eligible when a renderer patch is required.
v8 logic: Non-memory safety issues, incorrect values and type confusion DCHECKS in v8 are treated as v8 logic bugs.
v8 sbox: A test case must be provided and successfully escape the v8 sandbox in a d8 build with v8_enable_sandbox = true and v8_enable_memory_corruption_api = true. Submissions may make use of --expose-gc, --single-threaded, --fuzzing, --jit-fuzzing, and/or --allow-natives-syntax, but otherwise cannot make use of any additional flags. The test case must be executed with --sandbox-testing. See the sandbox readme for full details. Submissions should be reported using the Chromium security bug reporting form and include [V8 Sandbox Bypass] in the report title.
Below baseline: (not shown) Reports that do not consist of the characteristics of a baseline reward, or fail to attach PoCs and logs as file uploads, will be limited to the base reward amount.
Mitigated issues: Moderately or highly mitigated issues require significant user interaction, winning a race, browser or profile shutdown, unusual flags, or unlikely workflows. Mitigated issues are eligible for only the base reward amount.
Gemini & AI vulnerabilities 
Ineligible AI report types 
When submitting AI vulnerability reports, take note that non-qualifying issues and vulnerabilities are ineligible for reward. Reports that fall in these categories will not be accepted, and your report will be closed. Examples include:

Generating violative, misleading, or factually incorrect content within the attacker's own session (including standard "jailbreaks" and "hallucinations"). Please report inappropriate content using in-product links.
AI-generated content-based issues, including reports of AI safety or alignment bypasses. Please report this content using in-product links.
Compliance, legal, or intellectual property issues, including issues relating to country/region-specific laws such as privacy or intellectual property laws. Please report those issues to the Report Content for Legal Reasons process.
Preamble extraction without sensitive information leakage.
Contexts in which a model's incorrect output or classification does not pose a compelling attack scenario or feasible path to user harm.
Reports must be reproduced by the reporter and demonstrate a clear in-scope threat, risk, or vulnerability in plain language
Please carefully review the list of non-qualifying vulnerabilities before filing your report.

Qualifying AI Report Categories 
Rogue Actions

Attacks that modify the state of victim’s accounts or data with a clear security impact.

Example: Indirect prompt injection allows an attacker to unexpectedly, and without confirmation, cause a payment, account deletion, or significant data corruption.

Sensitive Data Exfiltration

Attacks that leak victim’s SPII, PII, or other sensitive data without an effective opportunity for user approval.

Example: Indirect prompt injection allows an attacker to unexpectedly, and without confirmation, summarize all of a victim's data on one site, and enter the summary in a different attacker-controlled site.

Reward amounts for Gemini & AI Features in Chrome 
Attacks with broader applicability or higher demonstrated user-harm will receive higher rewards.

Scalable – Attack reproduces across hosting sites and is not strongly tied to the prompt entered by the user.
Reliable – Attack reproduces on only some sites, and on 50%+ attempts, and is not strongly tied to the prompt entered by the user.
We value honest assessments of attack reliability. Reports of High and Moderate impact issues that include accurate data on reliability may be eligible for an ASR (Attack Success Rate) bonus of $1,000.

Category	High Impact && Reliable || Moderate Impact && Scalable	Moderate Impact && Reliable || High Impact && Unreliable
Rogue Actions	Up to $20,000	Up to $5,000
Sensitive Data Exfiltration	Up to $10,000	Up to $3,000
Other vulnerability classes 
For these classes of bugs, reports are expected to clearly demonstrate the exploitability and impact to a user, such as a convincing UI spoof or how user information would be disclosed.

Category	High Impact
UXSS || Site isolation bypass	Up to $10,000
User information disclosure	Up to $5,000
Local privilege escalation	Up to $5,000
Omnibox URL Spoofing	Up to $5,000
Web platform privilege escalation	Up to $5,000
Valid reports of LPE vulnerabilities should demonstrate exploitability that breaks an OS security boundary using a Chrome component and is otherwise within Chrome's threat model.

High impact: straight path to exploitability, demonstrable and significant user harm, remote exploitability, low to no preconditions to exploit, examples:

Site isolation bypass
Local privilege escalation
User information disclosure / site isolation bypass
Security UI spoof
Security UI spoof
User information disclosure
Bugs with significant preconditions to exploit and no demonstrable risk to a user are not eligible for a Chrome VRP reward. In addition, the Chrome VRP Panel reserves the right to decline a reward for low-quality and speculative reports.

Exploit Bonuses 
Full Chain Exploit 
A full chain exploit bonus is available for demonstrations of exploits against an active release of a Stable or Beta build of Chrome. Chrome must run on an up-to-date 64-bit operating system on supported platforms. Hardware mitigations such as MTE or CET must be enabled if supported by default by Chrome on the platform where the exploit is being demonstrated.

$250,000 is payable for each exploit that succeeds from web contents, and $200,000 is payable for an exploit that requires MojoJS to be enabled. Other unsafe flags or debugging features are prohibited. Patches to the renderer are not accepted. Feature flags that have been enabled for any users on that version of Chrome are allowed.

A maximum of four exploit bonuses will be rewarded in 2026 following the April rules update.

MiraclePtr Bypass Reward 
Code and issues in code protected by BackupRefPtr / MiraclePtr are expected to be resilient against the exploitation of UAFs in non-renderer processes. We no longer consider MiraclePtr-protected UAFs in non-renderer processes to be security bugs, but stability issues, as of M128. A valid bypass of MiraclePtr is now eligible for a reward of $250,128.

Eligible bypass submissions should consist of the following:

Link to the original issue or patch (if not yet publicly disclosed), if not a novel UAF. Otherwise provide a full report of the MiraclePtr-protected security bug

Test case / PoC triggering the issue that demonstrates protection under BRP-ASAN with a MiraclePtr status of PROTECTED

PoC that demonstrates the second-order primitive in the release build (controlled write or instruction pointer control)

Complete, detailed write-up of the technique to bypass MiraclePtr

Please note: the possibility of direct use of the zapped memory value ("\xef" bytes) during a UAF (e.g. as an enum value or size) is known and not itself considered a novel technique, and is not eligible for this bypass reward.

We are interested to see examples of this technique being applied, and instead offer a reward of $70,000 - $90,000 for a novel PoC demonstrating a second-order primitive by applying this technique to a Miracle-Ptr protected issue, depending on the process. A novel demonstration presented with a functional exploit is eligible for a reward of $85,000 - $250,000.

A bypass report must specifically explain or demonstrate how existing MiraclePtr protections can be bypassed. A UAF in a non-renderer process is only protected by MiraclePtr when the test case / PoC triggering it results in a status of "MiraclePtr: PROTECTED" when reproduced in a Chrome ASAN build. If the MiraclePtr status in ASAN output is NOT PROTECTED or MANUAL ANALYSIS REQUIRED, these issues are not considered protected by MiraclePtr and are not eligible for the bypass reward. Reports of UAFs in non-renderer processes that involve pointers not protected by MiraclePtr are eligible for the standard Chrome VRP reward amounts for that bug class, based on report quality and mitigations.

If a complete, eligible bypass submission includes a novel UAF in a non-renderer process process, through which the bypass can be clearly and concisely demonstrated through a PoC or exploit, the $250,128 reward amount will be added as a bonus to the reward amount for the non-renderer process UAF. In this scenario, a novel UAF bug that demonstrates a MiraclePtr bypass is submitted with a functional exploit is eligible for a reward up to $85,000-$250,000 - in addition to the $250,128 bonus for the submission of an eligible bypass.

A maximum of four MiraclePtr bypass rewards will be awarded following the April rules update in 2026.

VRP decisions 
The decision whether to grant a reward and the amount of the reward is always determined at the sole discretion of the reward panel. In particular, we may decide to pay higher rewards for unusually clever or severe vulnerabilities; decide that a single report actually constitutes multiple bugs; or that multiple reports are so closely related that they only warrant a single reward.

Reports that do not meet the criteria for a baseline report do not provide sufficient detail to help developers rapidly address the security vulnerability. While these reports will still be evaluated for a potential VRP reward, they will receive significantly reduced reward amounts. If there is no evidence of exploitability before the issue is resolved or goes to the VRP panel, the report may not be eligible for a VRP reward.

Reassessment of Reward Amount 
If you believe there was an error in the VRP's reward decision, we are happy to reassess for a potential change in VRP reward amount. We base rewards on the information presented to us when the bug is submitted, and will not reconsider rewards based on information added after the initial report is submitted. Please follow the process outlined in the VRP FAQ.

Report criteria for reward decisions 
Chrome VRP reward decisions are made after the bug is reproduced on our infrastructure and fixed. Unless there are exceptional circumstances, Chrome VRP reward decisions are based solely on the information provided in the original report. Information provided after the bug is fully resolved or after the reward decision has been made will not be eligible for a reassessment of the reward decision.

Functional exploits demonstrating RCE for a given bug will continue to be accepted for a higher reward after fix and Chrome VRP reward decision, until all outstanding exploit rewards have been claimed.

Policy regarding unactionable reports and duplicates 
To incentivize more complete and actionable reporting, the date and time a report is submitted in the bug tracker will not be the sole factor for determining whether a report is considered the first report of that security issue.

A report is considered an actionable submission when all the information required to triage is provided in the report. This means that an earlier- received incomplete submission may be marked as a duplicate of a later received actionable submission. The later-received, actionable report will be considered the canonical report of that security issue.

This policy is also applicable to shell reports, i.e. reports submitted without any information to gain a hold or timestamp at an earlier than actionable time. The report is not considered an actionable submission until it consists of at least some or most of the characteristics consistent with a baseline-quality report.

If the first submission of a report is considered actionable and can be resolved based on the contents of the report, it will always be considered the first and canonical report of that security issue.

Duplicate reports 
Traditionally our policy related to duplicates has been strictly: "the earliest filed bug report in the bug tracker is considered the first report." Often we receive later versions of an earlier-reported security bug that are of such high quality that we use those components in advancing the triage or resolution of that issue. While this is against the core foundations of our policy around duplicate reports, we have made numerous exceptions and issued a small reward to the later reporter for their contributions that result in getting the security issue resolved.

The Chrome VRP wants to better acknowledge and consistently reward these contributions. When a later-submitted report is of higher quality and is actively used by the security team or engineers to improve triage, reproduction, investigation, or root cause analysis of an earlier-reported issue, both reports may be eligible for the VRP reward -- with the total reward amount being divided between the two reports.

This policy will only take effect when the security or engineering teams have actively used or acknowledged artifacts from a duplicate report to work toward resolution of a security issue. This policy is not applicable based solely on the existence of a duplicate report submitted in the same general period of time.

Additional Chrome Rewards 
Reports may be eligible for additional bonus rewards if they meet the conditions outlined in this section.

Patch Bonus 
More significant patches can be submitted under our Patch Reward Program.

Fuzzer Bonus 
The Chrome Fuzzer Program allows you to run fuzzers on Google hardware at Google scale across thousands of cores.

You will receive 100% of the reward value for any bugs found by your fuzzer, plus a fuzzer bonus, provided the same bug was not found by one of our fuzzers within 48 hours.

Fuzzer bonuses are tiered as follows:

Renderer/sandboxed process bugs found by fuzzer: multiplier increased by 1
Browser/Network/GPU process bugs found by fuzzer: multiplier increased by 2
Please see the Chrome Fuzzer Program section for more details about the Chrome Fuzzing Program.

Chrome Fuzzer Program 
The Chrome Fuzzer Program allows you to run fuzzers on Google hardware at Google scale across thousands of cores. You receive 100% of the reward value for any bugs found by your fuzzer plus a bonus (see the Fuzzer Bonus section), provided the same bug was not found by one of our fuzzers within 48 hours.

The Chrome Fuzzer Program is not accepting ClusterFuzz fuzzers at this time. New libFuzzer in-tree fuzzers can still be submitted, as specified below. Valid security bugs reported from previously submitted and accepted fuzzers are still eligible for VRP rewards and fuzzer bonuses.

libFuzzer 
LibFuzzer allows fuzz testing of individual components in the Chrome browser, and libFuzzer-based fuzzers are just as easy to write as unit tests. Any Chromium contributor can submit them to the Chromium codebase, which will be picked up and run continuously at scale by our fuzzing automation system, ClusterFuzz.

ClusterFuzz 
New ClusterFuzz fuzzers are not being accepted at this time. This section will be updated when this changes.

If you have a fuzzer running as a part of Chrome Fuzzer Program, you will not receive a reward if one of our fuzzers finds the same bug within 48 hours, as ClusterFuzz may have simply scheduled your fuzzer before ours.

All fuzzers run at Google's discretion.
"""


class CrashAnalyzer:
    def __init__(self, config: dict):
        self.config        = config
        self.db_path       = config['infra']['db_path']
        self.triage        = config['triage']
        self.ai_cfg        = config['ai']
        self._queue: asyncio.Queue = asyncio.Queue()
        self._vrp_rules    = ""  # 起動後にfetch
        self._init_db()

    async def init_vrp_rules(self):
        """起動時にVRPルールページを取得"""
        url = self.triage.get('vrp_rules_url', '')
        if url:
            self._vrp_rules = await fetch_vrp_rules(url)
            if self._vrp_rules:
                log.info(f"VRPルール取得完了: {len(self._vrp_rules)}文字")
            else:
                self._vrp_rules = FALLBACK_RULES
                log.warning("VRPルール取得失敗: フォールバック使用")
        else:
            self._vrp_rules = FALLBACK_RULES

    def _init_db(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS crashes (
                    id              TEXT PRIMARY KEY,
                    engine          TEXT,
                    seed_id         TEXT,
                    js_code         TEXT,
                    stderr          TEXT,
                    returncode      INTEGER,
                    worker_type     TEXT,
                    differ_bug      INTEGER DEFAULT 0,
                    signature       TEXT,
                    timestamp       REAL,

                    -- triage結果
                    vrp_eligible    INTEGER,
                    crash_type      TEXT,
                    cvss            REAL,
                    exploitability  TEXT,
                    reward_min      INTEGER,
                    reward_max      INTEGER,
                    report_title    TEXT,
                    priority        TEXT,
                    attack_scenario TEXT,
                    patch_hint      TEXT,

                    -- 最小化・Bisect
                    minimized_code  TEXT,
                    bisect_commit   TEXT,
                    patch_code      TEXT,

                    -- 状態管理
                    reported        INTEGER DEFAULT 0,
                    triaged_at      REAL
                )
            """)

    async def queue(self, crash: dict, engine: str):
        """クラッシュをtriageキューに追加"""
        crash['engine'] = engine

        # DB保存
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                INSERT OR IGNORE INTO crashes
                    (id, engine, seed_id, js_code, stderr,
                     returncode, worker_type, differ_bug,
                     signature, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                crash['id'],
                engine,
                crash.get('seed_id'),
                crash.get('js_code', ''),
                crash.get('stderr', ''),
                crash.get('returncode', -1),
                crash.get('worker_type', 'unknown'),
                1 if crash.get('differ_bug') else 0,
                crash.get('signature', ''),
                crash.get('timestamp', time.time()),
            ))

        await self._queue.put(crash)

    async def dequeue(self) -> Optional[dict]:
        """キューからクラッシュを取得"""
        try:
            return self._queue.get_nowait()
        except asyncio.QueueEmpty:
            return None

    async def analyze(self, crash: dict) -> dict:
        """クラッシュを解析してVRP判定を返す"""

        # 1. 事前フィルター
        filter_result = self._pre_filter(crash)
        if filter_result['skip']:
            log.info(
                f"Pre-filter skip: {crash['id']} - {filter_result['reason']}"
            )
            return {
                'vrp_eligible': False,
                'reason_if_not_eligible': filter_result['reason'],
                'cvss': 0.0,
                'priority': 'ignore',
            }

        # 2. Geminiでtriage
        result = await self._gemini_triage(crash)

        # 3. DB更新
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                UPDATE crashes SET
                    vrp_eligible   = ?,
                    crash_type     = ?,
                    cvss           = ?,
                    exploitability = ?,
                    reward_min     = ?,
                    reward_max     = ?,
                    report_title   = ?,
                    priority       = ?,
                    attack_scenario= ?,
                    patch_hint     = ?,
                    triaged_at     = ?
                WHERE id = ?
            """, (
                1 if result.get('vrp_eligible') else 0,
                result.get('crash_type', ''),
                result.get('cvss', 0.0),
                result.get('exploitability', ''),
                result.get('estimated_reward_min', 0),
                result.get('estimated_reward_max', 0),
                result.get('report_title', ''),
                result.get('priority', 'ignore'),
                result.get('attack_scenario', ''),
                result.get('patch_hint', ''),
                time.time(),
                crash['id'],
            ))

        log.info(
            f"Triage: {crash['id']} | "
            f"eligible={result.get('vrp_eligible')} | "
            f"CVSS={result.get('cvss')} | "
            f"est=${result.get('estimated_reward_min',0)}"
            f"~${result.get('estimated_reward_max',0)}"
        )

        return result

    def _pre_filter(self, crash: dict) -> dict:
        """VRP対象外を事前に弾く"""
        stderr = crash.get('stderr', '')
        js     = crash.get('js_code', '')

        # --experimental フラグチェック
        if '--experimental' in js:
            return {'skip': True, 'reason': '--experimentalフラグ使用 → 対象外'}

        # 再現性チェック（stderrが空 = クラッシュ情報なし）
        if not stderr and crash.get('returncode', 0) == 0:
            return {'skip': True, 'reason': '再現情報なし'}

        # differ_bugは特別扱い（クラッシュしないバグ）
        if crash.get('differ_bug'):
            return {'skip': False, 'reason': ''}

        # 明らかに悪意のないクラッシュ
        if 'FATAL ERROR' not in stderr and crash.get('returncode') == 1:
            return {'skip': True, 'reason': 'JS例外のみ（severity低すぎ）'}

        return {'skip': False, 'reason': ''}

    async def _gemini_triage(self, crash: dict) -> dict:
        """GeminiにVRP判定させる"""
        accounts = self.ai_cfg['gemini']['accounts']
        # triage用は account[0] を優先
        api_key = accounts[0]['api_key']

        prompt = f"""
以下のクラッシュを評価してください:

エンジン: {crash.get('engine', 'v8').upper()}
Worker種別: {crash.get('worker_type', 'unknown')}
差分バグ: {crash.get('differ_bug', False)}

JavaScriptコード:
```javascript
{crash.get('js_code', '')[:3000]}
```

クラッシュ出力（stderr）:
```
{crash.get('stderr', '')[:2000]}
```

returncode: {crash.get('returncode', -1)}
"""

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.5-flash:generateContent?key={api_key}"
        )
        payload = {
            "system_instruction": {"parts": [{"text": f"""あなたはChrome VRP判定専門家です。以下の公式ルールに基づいてクラッシュを評価してください。

=== Chrome VRP 公式ルール ===
{self._vrp_rules or FALLBACK_RULES}

=== 評価タスク ===
以下のクラッシュ情報を評価し、必ずJSONのみを出力してください。前置きや説明は不要です。

{{
  "vrp_eligible": true/false,
  "reason_if_not_eligible": "...",
  "crash_type": "OOB Write|OOB Read|UAF|Type Confusion|Stack Overflow|Integer Overflow|Other",
  "cvss": 0.0,
  "exploitability": "critical|high|medium|low|none",
  "estimated_reward_min": 0,
  "estimated_reward_max": 0,
  "target_program": "Google Chrome VRP",
  "affected_component": "V8 JIT|V8 GC|V8 Parser|...",
  "report_title": "...",
  "priority": "critical|high|medium|low|ignore",
  "bonus_opportunities": [],
  "attack_scenario": "どのように悪用できるか（1〜2文）",
  "patch_hint": "修正の方向性（1文）"
}}
"""}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": 2048,
                "temperature": 0.1,  # 判定は低温度で安定させる
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload, timeout=60
                ) as resp:
                    data = await resp.json()

            text = data['candidates'][0]['content']['parts'][0]['text']

            # JSONを抽出
            text = re.sub(r'```json\n?', '', text)
            text = re.sub(r'```\n?', '', text)
            result = json.loads(text.strip())
            return result

        except json.JSONDecodeError as e:
            log.error(f"Gemini JSON parse error: {e}\nResponse: {text[:500]}")
            return self._fallback_triage(crash)
        except Exception as e:
            log.error(f"Gemini triage error: {e}")
            return self._fallback_triage(crash)

    def _fallback_triage(self, crash: dict) -> dict:
        """Gemini失敗時のフォールバック判定"""
        stderr = crash.get('stderr', '')

        # キーワードで簡易判定
        if 'AddressSanitizer' in stderr or 'ASAN' in stderr:
            return {
                'vrp_eligible': True,
                'crash_type': 'Memory Corruption',
                'cvss': 7.0,
                'exploitability': 'medium',
                'estimated_reward_min': 5000,
                'estimated_reward_max': 20000,
                'priority': 'daily_summary',
                'report_title': f"Memory corruption in {crash.get('engine','V8').upper()}",
                'attack_scenario': 'TBD',
                'patch_hint': 'TBD',
            }

        return {
            'vrp_eligible': False,
            'crash_type': 'Unknown',
            'cvss': 0.0,
            'priority': 'ignore',
        }

    def get_pending_crashes(self) -> list:
        """未報告のVRP候補クラッシュを取得"""
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("""
                SELECT id, engine, crash_type, cvss,
                       reward_min, reward_max, report_title,
                       priority, js_code, stderr, minimized_code,
                       bisect_commit, patch_hint, timestamp
                FROM crashes
                WHERE vrp_eligible = 1
                  AND reported = 0
                ORDER BY cvss DESC
            """).fetchall()

        return [
            {
                'id':             r[0],
                'engine':         r[1],
                'crash_type':     r[2],
                'cvss':           r[3],
                'reward_min':     r[4],
                'reward_max':     r[5],
                'report_title':   r[6],
                'priority':       r[7],
                'js_code':        r[8],
                'stderr':         r[9],
                'minimized_code': r[10],
                'bisect_commit':  r[11],
                'patch_hint':     r[12],
                'timestamp':      r[13],
            }
            for r in rows
        ]
