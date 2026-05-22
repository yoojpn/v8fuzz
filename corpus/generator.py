"""
SeedGenerator: SeedMind式のseed生成
・Geminiにジェネレーター関数を作らせる
・1 APIコール → ジェネレーター → 無限のseed
・仮説駆動（AFuzz式）
・Gerritコードレビューコメントを活用
"""
import asyncio
import json
import logging
import time
from pathlib import Path
from typing import List, Optional

import aiohttp

log = logging.getLogger('generator')


# V8狙いのシステムプロンプト
V8_SYSTEM_PROMPT = """
あなたはV8 JavaScriptエンジンのQAエンジニアです。
V8エンジンの動作を網羅的に検証するためのJavaScriptテストケースを生成する
Pythonジェネレーター関数を作成してください。

重要な制約:
1. --allow-natives-syntaxフラグで動作するd8向けのJS
2. %OptimizeMaglevOnNextCall, %PrepareFunctionForOptimization等のネイティブ構文を使う
3. エンジンの最適化パスを幅広くカバーするパターンを優先する
4. 既存のテストスイートでカバーされていない新しいパターンを生成する
5. コードのみ出力（説明不要）

検証すべき領域:
- Maglev JIT コンパイラの型推論の正確性
- TurboFan最適化の境界条件での動作
- GC中のオブジェクト移動と参照の整合性
- JS↔Wasm型変換境界での値の正確性
- Proxy/Reflectと最適化の相互作用
- 新仕様（Temporal, Records & Tuples等）の実装の正確性

出力形式（必ずこの形式でPythonコードのみ出力）:
```python
import random

def generate():
    # ジェネレーター関数
    while True:
        # パラメータをランダムに組み合わせてJSを生成
        yield f\"\"\"...\"\"\".format(...)
```
"""

JSC_SYSTEM_PROMPT = """
あなたはJavaScriptCore（WebKit）のQAエンジニアです。
JSCエンジンの動作を網羅的に検証するためのJavaScriptテストケースを生成する
Pythonジェネレーター関数を作成してください。

重要な制約:
1. jscバイナリ向けのJS（Linux環境）
2. $vm.ftlTrue(), $vm.dfgTrue(), $vm.gcAndSweep()等を使う
3. Linux環境固有の動作パスを優先的にカバーする
4. DFG JIT・FTL JITの最適化パスを幅広く検証する
5. コードのみ出力

検証すべき領域:
- DFG JITの型推論の正確性
- FTL JIT（B3/Air）の最適化での値の整合性
- Wasm memory64の境界動作
- Linux環境でのメモリ配置と参照の整合性
- 新JS仕様の実装の正確性

出力形式（必ずこの形式でPythonコードのみ出力）:
```python
import random

def generate():
    while True:
        yield f\"\"\"...\"\"\".format(...)
```
"""


class GeminiClient:
    """Gemini APIクライアント（複数アカウントローテーション＋レート制限対応）

    無料枠の制約:
      - RPM (requests per minute): 10 rpm / アカウント (gemini-2.5-flash)
      - RPD (requests per day):    1,500 rpd / アカウント
      - TPM (tokens per minute):   250,000 tpm / アカウント

    戦略:
      1. daily_limitを24hで割って均等ペース配分 → 朝に枯渇しない
      2. 429が来たらそのアカウントを一時ブロックし、別アカウントへ即切替
      3. 全アカウントが塞がっていたら retry-after に従ってスリープ
      4. 指数バックオフ（上限120s）で長時間429を回避
    """

    # 無料枠: gemini-2.5-flash は 10 RPM / アカウント
    RPM_LIMIT = 10
    # リクエスト間の最小間隔 (秒) = 60 / RPM + 余裕1秒
    MIN_INTERVAL = 60.0 / RPM_LIMIT + 1.0  # ~7s

    # 使用量永続化ファイル（再起動後も累積を維持）
    USAGE_FILE = Path('/opt/v8fuzz/logs/gemini_daily_usage.json')

    def __init__(self, accounts: List[dict], model: str = "gemini-2.5-flash"):
        self.accounts = accounts
        self.model    = model

        n = len(accounts)
        self.blocked_until = [0.0] * n
        self.last_call     = [0.0] * n

        # 使用量をファイルから復元（再起動後も累積を維持）
        self.usage = self._load_usage(n)

    def _load_usage(self, n: int) -> list:
        """ファイルから今日の使用量を読み込む。日付が変わっていたら0にリセット。"""
        import datetime, json
        today = datetime.date.today().isoformat()
        try:
            if self.USAGE_FILE.exists():
                data = json.loads(self.USAGE_FILE.read_text())
                if data.get('date') == today:
                    usage = data.get('usage', [0] * n)
                    # アカウント数が変わった場合に備えてpadding
                    while len(usage) < n:
                        usage.append(0)
                    log.info(f"Restored daily usage from file: {usage} (date={today})")
                    return usage[:n]
        except Exception as e:
            log.warning(f"Failed to load usage file: {e}")
        log.info(f"Starting fresh daily usage counter for {today}")
        return [0] * n

    def _save_usage(self):
        """今日の使用量をファイルへ書き出す。"""
        import datetime, json
        today = datetime.date.today().isoformat()
        try:
            self.USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
            self.USAGE_FILE.write_text(json.dumps({'date': today, 'usage': self.usage}))
        except Exception as e:
            log.warning(f"Failed to save usage file: {e}")

    # ------------------------------------------------------------------ #
    # 内部ユーティリティ
    # ------------------------------------------------------------------ #

    def _pick_account(self) -> Optional[int]:
        """ブロックされておらず daily_limit 未満のアカウントを使用数が少ない順に返す"""
        # 日付が変わっていたら使用量をリセット
        import datetime
        today = datetime.date.today().isoformat()
        saved = self._load_usage(len(self.accounts))
        # _load_usageが今日付けのデータを返す場合はそのまま使う
        # 日付が変わっていれば0リセット済みのリストが返ってくる
        self.usage = saved

        now = time.monotonic()
        candidates = []
        for i, acc in enumerate(self.accounts):
            limit = acc.get('daily_limit', 750)
            if self.usage[i] >= limit:
                continue
            if self.blocked_until[i] > now:
                continue
            candidates.append(i)
        if not candidates:
            return None
        # 使用量が最も少ないものを選ぶ
        return min(candidates, key=lambda i: self.usage[i])

    def _soonest_unblock(self) -> float:
        """全アカウントがブロック中のとき、最短で解除される秒数を返す"""
        now = time.monotonic()
        return max(0.0, min(self.blocked_until) - now)

    async def _throttle(self, idx: int):
        """RPM制限を守るため前回呼び出しからMIN_INTERVAL秒待つ"""
        elapsed = time.monotonic() - self.last_call[idx]
        wait = self.MIN_INTERVAL - elapsed
        if wait > 0:
            log.debug(f"  [acct {idx}] RPM throttle: sleeping {wait:.1f}s")
            await asyncio.sleep(wait)

    # ------------------------------------------------------------------ #
    # 公開API
    # ------------------------------------------------------------------ #

    async def generate(self, prompt: str, system: str) -> str:
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": 8192,
                "temperature": 0.9,
            }
        }
        timeout = aiohttp.ClientTimeout(total=120, connect=10)

        backoff = 15.0  # 初期バックオフ秒
        max_backoff = 120.0

        while True:
            idx = self._pick_account()

            if idx is None:
                # 全アカウント使用済み or ブロック中
                wait = self._soonest_unblock()
                if wait > 0:
                    log.warning(f"All accounts blocked. Waiting {wait:.0f}s for earliest unblock...")
                    await asyncio.sleep(wait + 1)
                else:
                    # daily_limit超過 → 本日分の予算切れ
                    raise Exception("Daily request budget exhausted for all accounts")
                continue

            await self._throttle(idx)

            api_key = self.accounts[idx]['api_key']
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{self.model}:generateContent?key={api_key}"
            )

            self.last_call[idx] = time.monotonic()
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(url, json=payload) as resp:
                        if resp.status == 429:
                            # retry-after ヘッダーがあればそれを使う
                            retry_after = float(resp.headers.get("Retry-After", backoff))
                            retry_after = min(retry_after, max_backoff)
                            log.warning(
                                f"[acct {idx}] 429 rate-limited. "
                                f"Blocking for {retry_after:.0f}s, switching account."
                            )
                            self.blocked_until[idx] = time.monotonic() + retry_after
                            backoff = min(backoff * 2, max_backoff)
                            continue  # 別アカウントで再試行

                        if resp.status == 503:
                            log.warning(f"[acct {idx}] 503 unavailable. Retry in {backoff:.0f}s")
                            await asyncio.sleep(backoff)
                            backoff = min(backoff * 2, max_backoff)
                            continue

                        if resp.status != 200:
                            text = await resp.text()
                            raise Exception(f"Gemini API error {resp.status}: {text[:200]}")

                        data = await resp.json()
                        self.usage[idx] += 1
                        self._save_usage()
                        backoff = 15.0  # 成功したらバックオフをリセット
                        return data['candidates'][0]['content']['parts'][0]['text']

            except asyncio.TimeoutError:
                log.warning(f"[acct {idx}] Timeout. Retry in {backoff:.0f}s")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)
            except Exception as e:
                if "budget exhausted" in str(e):
                    raise
                log.error(f"[acct {idx}] Unexpected error: {e}. Retry in {backoff:.0f}s")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)

    def get_daily_usage(self) -> dict:
        return {i: self.usage[i] for i in range(len(self.accounts))}


class SeedGenerator:
    def __init__(self, config: dict):
        self.config  = config
        self.gemini  = GeminiClient(
            config['ai']['gemini']['accounts'],
            model=config['ai']['gemini'].get('model', 'gemini-2.5-flash'),
        )
        self.batch   = config['ai']['gemini'].get('batch_size', 3)
        self.per_req = config['ai']['gemini'].get('seeds_per_request', 200)

        # 生成済みジェネレーターをキャッシュ
        self._generators_v8:  List = []
        self._generators_jsc: List = []

    async def generate_stream(self, engine: str, corpus) -> None:
        """
        seedを生成しながら即座にcorpusへ流し込む（ストリーミング生成）。
        fuzz loopはcorpusにseedが入り次第すぐ動き始める。

        ペーシング戦略:
          seed_generation (例: 1200 req) を 2h に均等分散。
          pace = 7200s / budget → budget=1200 なら 6秒/req。
          RPM上限(10rpm=6s/req)とほぼ一致するので自然に収まる。
        """
        alloc  = self.config['ai']['allocation']
        budget = alloc['seed_generation']  # req/サイクル

        # 2h (7200s) で budget リクエストを均等に消化するペース
        pace_interval = 7200.0 / budget
        log.info(
            f"[{engine}] Stream generation start: budget={budget} req, "
            f"pace={pace_interval:.1f}s/req (2h window)"
        )

        system = V8_SYSTEM_PROMPT if engine == 'v8' else JSC_SYSTEM_PROMPT
        total_seeds = 0

        for i in range(0, budget, self.batch):
            try:
                log.debug(f"  [{engine}] Building prompt for batch {i}...")
                prompt   = self._build_batch_prompt(engine, batch_num=i)
                log.debug(f"  [{engine}] Calling Gemini API (batch {i})...")
                response = await self.gemini.generate(prompt, system)
                log.debug(f"  [{engine}] Gemini responded ({len(response)} chars): {response[:200]!r}")

                generators = self._extract_generators(response)
                log.debug(f"  [{engine}] Extracted {len(generators)} generator(s)")

                batch_seeds = []
                for j, gen_func in enumerate(generators):
                    log.debug(f"  [{engine}] Running generator {j+1}/{len(generators)}...")
                    new_seeds = self._run_generator(gen_func, engine, count=self.per_req)
                    batch_seeds.extend(new_seeds)
                    log.debug(f"  [{engine}] Generator {j+1} produced {len(new_seeds)} seeds")

                # ★ 生成できたらすぐcorpusへ追加（fuzz loopが即座に拾う）
                if batch_seeds:
                    added = await corpus.add_seeds(batch_seeds)
                    total_seeds += added
                    log.info(
                        f"  [{engine}] Batch {i}: {len(generators)} gen → "
                        f"+{added} seeds (corpus total {total_seeds})"
                    )

                # RPM制限はGeminiClient内で管理。ここでは2h均等分散のペースを守る
                pace = max(0.0, pace_interval * self.batch - GeminiClient.MIN_INTERVAL * self.batch)
                if pace > 0:
                    log.debug(f"  [{engine}] Pacing sleep {pace:.1f}s")
                    await asyncio.sleep(pace)

            except Exception as e:
                if "budget exhausted" in str(e):
                    log.info(f"[{engine}] Daily budget exhausted, stopping generation.")
                    break
                log.error(f"[{engine}] Seed generation error (batch {i}): {e}")
                await asyncio.sleep(10)

        log.info(f"[{engine}] Stream generation complete: {total_seeds} seeds added to corpus")

    async def generate_batch(self, engine: str) -> List[dict]:
        """後方互換用ラッパー（commit_watcher / generate_cve_seeds等から呼ばれる場合）"""
        alloc  = self.config['ai']['allocation']
        budget = alloc['seed_generation']
        system = V8_SYSTEM_PROMPT if engine == 'v8' else JSC_SYSTEM_PROMPT
        seeds  = []
        for i in range(0, budget, self.batch):
            try:
                prompt   = self._build_batch_prompt(engine, batch_num=i)
                response = await self.gemini.generate(prompt, system)
                for gen_func in self._extract_generators(response):
                    seeds.extend(self._run_generator(gen_func, engine, count=self.per_req))
                await asyncio.sleep(max(0.5, GeminiClient.MIN_INTERVAL * self.batch))
            except Exception as e:
                if "budget exhausted" in str(e):
                    break
                log.error(f"generate_batch error (batch {i}): {e}")
                await asyncio.sleep(10)
        return seeds

    async def generate_for_commit(self, commit: dict) -> List[dict]:
        """
        特定のコミットを狙ったseedを生成
        新コミット検知時に呼ばれる
        """
        engine = commit['engine']
        system = V8_SYSTEM_PROMPT if engine == 'v8' else JSC_SYSTEM_PROMPT

        prompt = f"""
以下のコミットを狙ったJavaScriptテストケースのジェネレーター関数を
{self.batch}個生成してください。

コミット情報:
  hash: {commit['hash'][:8]}
  message: {commit['message']}
  risk_score: {commit['risk_score']:.1f}

このコミットで変更されたコードの脆弱な点を推測し、
その弱点を突くJSを生成するジェネレーターを作成してください。
"""

        try:
            log.debug(f"Calling Gemini for commit {commit['hash'][:8]}...")
            response = await self.gemini.generate(prompt, system)
            log.debug(f"Gemini responded ({len(response)} chars)")
            generators = self._extract_generators(response)
            log.debug(f"Extracted {len(generators)} generator(s) for commit")
            seeds = []
            for gen_func in generators:
                new_seeds = self._run_generator(gen_func, engine, count=50)
                seeds.extend(new_seeds)
                log.debug(f"  Generator produced {len(new_seeds)} seeds")
            log.info(
                f"Commit-targeted seeds: {commit['hash'][:8]} → "
                f"{len(seeds)} seeds"
            )
            return seeds
        except Exception as e:
            log.error(f"Commit seed generation error: {e}")
            return []

    async def generate_cve_seeds(
        self, cve_description: str, engine: str
    ) -> List[dict]:
        """
        過去CVEのroot causeから同族バグを狙うseedを生成（AFuzz式）
        """
        system = V8_SYSTEM_PROMPT if engine == 'v8' else JSC_SYSTEM_PROMPT

        prompt = f"""
以下のCVEのroot causeと同じ種類のバグを見つけるための
ジェネレーター関数を{self.batch}個生成してください。

CVE情報:
{cve_description}

同じroot cause（型混乱・OOB・UAFなど）を持つ
「まだ発見されていない」バグを狙ってください。
"""

        try:
            response = await self.gemini.generate(prompt, system)
            generators = self._extract_generators(response)
            seeds = []
            for gen_func in generators:
                seeds.extend(
                    self._run_generator(gen_func, engine, count=100)
                )
            return seeds
        except Exception as e:
            log.error(f"CVE seed generation error: {e}")
            return []

    def _build_batch_prompt(self, engine: str, batch_num: int) -> str:
        """バッチプロンプト: 1 reqに複数の仮説を詰め込む"""
        hypotheses = [
            "Maglevコンパイラが型フィードバックをリセットしない場合",
            "GC中にオブジェクトのMapが変更される場合",
            "ProxyがJIT最適化を阻害する場合",
            "配列の穴（HOLEY）がSMI配列として最適化される場合",
            "BigIntとNumberの暗黙の型変換が発生する場合",
            "IteratorがGCで回収される場合",
            "WeakRefのオブジェクトがJITキャッシュに残る場合",
            "Temporalオブジェクトの境界値処理",
            "Wasm↔JS境界での型変換エラー",
            "SharedArrayBufferのレース条件",
        ]

        # batch_numで仮説を選択（毎日違う仮説）
        selected = []
        for i in range(self.batch):
            idx = (batch_num + i) % len(hypotheses)
            selected.append(f"{i+1}. {hypotheses[idx]}")

        return f"""
以下の{self.batch}つの仮説それぞれについて、
その仮説を検証するJSを生成するPythonジェネレーター関数を
1つずつ作成してください。

仮説:
{chr(10).join(selected)}

必ず{self.batch}個の独立した```python```コードブロックを出力してください。
各ブロックに1つのdef generate()関数を含めてください。
ブロックをまとめたり、1つにしないでください。

例（2つの場合）:
```python
import random
def generate():
    while True:
        yield "// test1"
```

```python
import random
def generate():
    while True:
        yield "// test2"
```
"""

    def _extract_generators(self, response: str) -> List[str]:
        """レスポンスからPythonジェネレーター関数を抽出"""
        import re

        # ```python ... ``` ブロックを抽出
        blocks = re.findall(
            r'```python\n(.*?)```',
            response,
            re.DOTALL
        )

        generators = []
        for block in blocks:
            if 'yield' not in block:
                continue
            # generate()以外の関数名にも対応: 最初のdef xxx()をgenerate()にリネーム
            if 'def generate()' not in block:
                block = re.sub(r'def (\w+)\(\):', 'def generate():', block, count=1)
            if 'def generate()' in block:
                generators.append(block)

        return generators

    def _run_generator(
        self, gen_code: str, engine: str, count: int = 20
    ) -> List[dict]:
        """ジェネレーター関数を実行してseedを生成"""
        import uuid

        seeds = []
        try:
            # ジェネレーター関数を動的に実行
            namespace = {}
            exec(gen_code, namespace)
            gen_func = namespace.get('generate')

            if gen_func is None:
                log.debug("  Generator: no generate() function found, skipping")
                return []

            gen = gen_func()
            for idx in range(count):
                try:
                    js_code = next(gen)
                    if isinstance(js_code, str) and len(js_code) > 10:
                        seeds.append({
                            'id':      uuid.uuid4().hex,
                            'code':    js_code,
                            'engine':  engine,
                            'source':  'ai_generator',
                            'created': time.time(),
                        })
                except StopIteration:
                    log.debug(f"  Generator exhausted after {idx} items")
                    break
                except Exception as e:
                    log.debug(f"  Generator item error: {e}")
                    continue

            log.debug(f"  _run_generator: produced {len(seeds)}/{count} seeds")

        except Exception as e:
            log.warning(f"Generator execution error: {e}")

        return seeds
