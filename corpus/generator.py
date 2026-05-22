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
    """Gemini APIクライアント（複数アカウントローテーション）"""

    def __init__(self, accounts: List[dict], model: str = "gemini-3.5-flash"):
        self.accounts = accounts
        self.model    = model
        self.current  = 0
        self.usage    = {i: 0 for i in range(len(accounts))}

    def _next_account(self) -> dict:
        """使用量が少ないアカウントを選択"""
        idx = min(self.usage, key=self.usage.get)
        self.usage[idx] += 1
        return self.accounts[idx]

    async def generate(self, prompt: str, system: str) -> str:
        account = self._next_account()
        api_key = account['api_key']
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={api_key}"
        )

        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": 8192,
                "temperature": 0.9,
            }
        }

        timeout = aiohttp.ClientTimeout(total=120, connect=10)
        for attempt in range(3):
            try:
                async def _call():
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.post(url, json=payload) as resp:
                            if resp.status in (429, 503):
                                return resp.status, None
                            if resp.status != 200:
                                text = await resp.text()
                                raise Exception(f"Gemini API error {resp.status}: {text}")
                            return 200, await resp.json()

                status, data = await asyncio.wait_for(_call(), timeout=130)

                if status in (429, 503):
                    wait = 10 * (attempt + 1)
                    log.warning(f"Gemini {status}, retry {attempt+1}/3 in {wait}s")
                    await asyncio.sleep(wait)
                    continue

                return data['candidates'][0]['content']['parts'][0]['text']

            except asyncio.TimeoutError:
                log.warning(f"Gemini socket hang detected (attempt {attempt+1}/3), retrying...")
                await asyncio.sleep(5)
            except Exception as e:
                log.error(f"Gemini error (attempt {attempt+1}/3): {e}")
                await asyncio.sleep(5)

        raise Exception("Gemini API failed after 3 retries")

    def get_daily_usage(self) -> dict:
        return dict(self.usage)


class SeedGenerator:
    def __init__(self, config: dict):
        self.config  = config
        self.gemini  = GeminiClient(config['ai']['gemini']['accounts'], model=config['ai']['gemini'].get('model', 'gemini-3.5-flash'))
        self.batch   = config['ai']['gemini'].get('batch_size', 3)
        self.per_req = config['ai']['gemini'].get('seeds_per_request', 20)

        # 生成済みジェネレーターをキャッシュ
        self._generators_v8:  List = []
        self._generators_jsc: List = []

    async def generate_batch(self, engine: str) -> List[dict]:
        """
        1日分のseedバッチを生成
        SeedMind式: ジェネレーター関数を生成してから実行
        """
        alloc  = self.config['ai']['allocation']
        budget = alloc['seed_generation']  # req/日
        seeds  = []

        system = V8_SYSTEM_PROMPT if engine == 'v8' else JSC_SYSTEM_PROMPT

        log.info(f"Generating seeds for {engine} ({budget} requests budget)")

        for i in range(0, budget, self.batch):
            try:
                # バッチプロンプト: 1 req に複数の仮説を詰め込む
                log.debug(f"  [{engine}] Building prompt for batch {i}...")
                prompt = self._build_batch_prompt(engine, batch_num=i)
                log.debug(f"  [{engine}] Calling Gemini API (batch {i})...")
                response = await self.gemini.generate(prompt, system)
                log.debug(f"  [{engine}] Gemini responded ({len(response)} chars): {response[:200]!r}")
                generators = self._extract_generators(response)
                log.debug(f"  [{engine}] Extracted {len(generators)} generator(s)")

                for j, gen_func in enumerate(generators):
                    log.debug(f"  [{engine}] Running generator {j+1}/{len(generators)}...")
                    # ジェネレーターを実行してseedを生成
                    new_seeds = self._run_generator(
                        gen_func, engine, count=self.per_req
                    )
                    seeds.extend(new_seeds)
                    log.debug(f"  [{engine}] Generator {j+1} produced {len(new_seeds)} seeds")

                log.info(
                    f"  Batch {i}: {len(generators)} generators → "
                    f"{len(seeds)} seeds total"
                )

                # レート制限対策
                await asyncio.sleep(0.5)

            except Exception as e:
                log.error(f"Seed generation error (batch {i}): {e}")
                await asyncio.sleep(5)

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

各ジェネレーターは独立したPython関数として出力してください。
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
            # generate() 関数が含まれているか確認
            if 'def generate()' in block and 'yield' in block:
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
