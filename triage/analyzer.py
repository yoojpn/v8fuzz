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

log = logging.getLogger('analyzer')


VRP_SYSTEM_PROMPT = """
あなたはChrome VRP（脆弱性報奨金プログラム）とApple Security Bountyの
判定専門家です。以下の公式ルールに基づいてクラッシュを正確に評価してください。

=== Chrome VRP 公式ルール ===

【対象】
- Stable / Beta / Dev チャンネルのバグ
- コミットから8日以上経過したバグ（7日ルール + バッファ）
- --experimental フラグが不要なバグ

【対象外】
- --experimental-* フラグが必要なバグ
- コマンドライン引数でのみ発生するバグ（一部例外あり）
- 既にパッチ済みのバグ

【報奨金レンジ（2024年8月改定）】
- RCE（非サンドボックス）: 最大$250,000
- サンドボックス脱出: $50,000〜$100,000
- OOB Write（exploitable）: $20,000〜$50,000
- Type Confusion（JIT）: $15,000〜$30,000
- OOB Read: $7,500〜$15,000
- UAF: $10,000〜$30,000
- Low severity / DoS: $500〜$3,000

【ボーナス】
- Bisect Bonus: 導入コミット特定で追加報奨金
- Patch Bonus: 修正パッチ提出で$500〜$2,000追加

=== Apple Security Bounty ルール ===

【報奨金レンジ（2025年改定）】
- WebKit RCE（サンドボックス脱出）: 最大$300,000
- Type Confusion: $50,000〜$150,000
- OOB Read/Write: $25,000〜$100,000
- Memory Corruption: $50,000〜$200,000

【注意】
- AIで生成した長い説明文は避ける（Appleが明示的に嫌う）
- 報告書はコンパクトで具体的に

=== 評価タスク ===

以下のクラッシュ情報を評価し、必ずJSONのみを出力してください。
前置きや説明は不要です。

{
  "vrp_eligible": true/false,
  "reason_if_not_eligible": "...",
  "crash_type": "OOB Write|OOB Read|UAF|Type Confusion|Stack Overflow|Integer Overflow|Other",
  "cvss": 0.0,
  "exploitability": "high|medium|low|none",
  "estimated_reward_min": 0,
  "estimated_reward_max": 0,
  "target_program": "Google Chrome VRP|Apple Security Bounty",
  "affected_component": "Maglev JIT|TurboFan|GC|Wasm|Proxy|Other",
  "report_title": "VRPタイトル案（英語・60文字以内）",
  "priority": "immediate|daily_summary|ignore",
  "bonus_opportunities": [],
  "attack_scenario": "どのように悪用できるか（1〜2文）",
  "patch_hint": "修正の方向性（1文）"
}
"""


class CrashAnalyzer:
    def __init__(self, config: dict):
        self.config   = config
        self.db_path  = config['infra']['db_path']
        self.triage   = config['triage']
        self.ai_cfg   = config['ai']
        self._queue: asyncio.Queue = asyncio.Queue()
        self._init_db()

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
            "system_instruction": {"parts": [{"text": VRP_SYSTEM_PROMPT}]},
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
