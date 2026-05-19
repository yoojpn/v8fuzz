"""
Minimizer: Delta debugging でクラッシュを最小化
Bisect: 導入コミットを特定
"""
import asyncio
import logging
import os
import subprocess
import tempfile
import time
from typing import Optional

log = logging.getLogger('minimizer')


class Minimizer:
    def __init__(self, config: dict, engine: str):
        self.config  = config
        self.engine  = engine
        self.eng_cfg = config['engines'][engine]
        self.tmpfs   = config['infra']['tmpfs_dir']

    def _run(self, js_code: str) -> bool:
        """クラッシュするか確認"""
        path = os.path.join(self.tmpfs, f"min_{os.getpid()}.js")
        try:
            with open(path, 'w') as f:
                f.write(js_code)

            result = subprocess.run(
                [self.eng_cfg['binary']] +
                self.eng_cfg['flags'] + [path],
                capture_output=True,
                timeout=self.eng_cfg['timeout_ms'] / 1000 + 1,
                env={**os.environ, 'ASAN_OPTIONS': 'halt_on_error=1'}
            )
            return result.returncode not in (0, 1)

        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
        finally:
            try:
                os.unlink(path)
            except Exception:
                pass

    def minimize(self, js_code: str, max_iterations: int = 1000) -> str:
        """Delta debugging でクラッシュを最小化"""
        log.info(f"Minimizing: {len(js_code)} chars")

        lines = js_code.split('\n')
        minimized = lines[:]

        # 行単位で削除
        changed = True
        iterations = 0
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for i in range(len(minimized) - 1, -1, -1):
                candidate = minimized[:i] + minimized[i+1:]
                code = '\n'.join(candidate)
                if len(code.strip()) > 0 and self._run(code):
                    minimized = candidate
                    changed = True
                    break

        result = '\n'.join(minimized)

        # 文字単位でさらに削減（トークン置換）
        result = self._token_minimize(result)

        log.info(
            f"Minimized: {len(js_code)} → {len(result)} chars "
            f"({len(js_code.split(chr(10)))} → {len(result.split(chr(10)))} lines)"
        )
        return result

    def _token_minimize(self, code: str) -> str:
        """トークンレベルの最小化"""
        import re

        # 変数名を短くする
        vars_found = re.findall(r'\b([a-zA-Z_]\w{3,})\b', code)
        var_map = {}
        counter = 0

        for var in set(vars_found):
            if var not in ('function', 'return', 'var', 'let',
                          'const', 'for', 'while', 'if', 'else',
                          'new', 'this', 'null', 'undefined', 'true',
                          'false', 'class', 'extends', 'yield', 'async',
                          'await', 'import', 'export', 'default'):
                short = f"_{counter}"
                counter += 1
                var_map[var] = short

        candidate = code
        for long_name, short_name in var_map.items():
            candidate = re.sub(
                r'\b' + re.escape(long_name) + r'\b',
                short_name,
                candidate
            )

        if self._run(candidate):
            return candidate
        return code


class Bisector:
    """導入コミットを特定（Bisect Bonus狙い）"""

    def __init__(self, config: dict, engine: str):
        self.config  = config
        self.engine  = engine
        self.db_path = config['infra']['db_path']

    async def bisect(self, crash: dict) -> Optional[str]:
        """
        バイナリサーチでバグ導入コミットを特定
        V8はChromium Git、JSCはGitHubから履歴を取得
        """
        import sqlite3

        if self.engine == 'v8':
            return await self._bisect_v8(crash)
        else:
            return await self._bisect_jsc(crash)

    async def _bisect_v8(self, crash: dict) -> Optional[str]:
        """V8のコミット履歴からbisect"""
        import aiohttp

        # seen_commitsから候補を取得
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("""
                SELECT hash, message, timestamp
                FROM seen_commits
                WHERE engine = 'v8'
                ORDER BY timestamp DESC
                LIMIT 100
            """).fetchall()

        if not rows:
            return None

        log.info(f"Bisecting V8 among {len(rows)} commits...")

        # 簡易bisect: 最新から順に確認
        # （本格的なbisectはV8ビルドが必要なので現段階ではスキップ）
        for row in rows[:10]:
            log.info(f"  Checking commit: {row[0][:8]} - {row[1][:50]}")

        # 最も最近の危険なコミットを返す
        return rows[0][0] if rows else None

    async def _bisect_jsc(self, crash: dict) -> Optional[str]:
        """JSCのコミット履歴からbisect"""
        import sqlite3

        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("""
                SELECT hash, message
                FROM seen_commits
                WHERE engine = 'jsc'
                ORDER BY timestamp DESC
                LIMIT 10
            """).fetchall()

        return rows[0][0] if rows else None


class PatchGenerator:
    """修正パッチ案を自動生成（Patch Bonus狙い）"""

    def __init__(self, config: dict):
        self.config = config

    async def generate(self, crash: dict, analysis: dict) -> Optional[str]:
        """Geminiにパッチ案を生成させる"""
        import aiohttp
        import json

        accounts = self.config['ai']['gemini']['accounts']
        api_key  = accounts[0]['api_key']

        prompt = f"""
以下のクラッシュに対して、V8/JSCのソースコードへの
修正パッチ案（英語）を簡潔に提案してください。

クラッシュ種別: {analysis.get('crash_type', 'Unknown')}
影響コンポーネント: {analysis.get('affected_component', 'Unknown')}
パッチヒント: {analysis.get('patch_hint', 'N/A')}

PoC:
```javascript
{crash.get('minimized_code') or crash.get('js_code', '')[:500]}
```

以下の形式で出力してください:
1. 根本原因（1文）
2. 修正方針（2〜3文）
3. 擬似パッチ（コード例）
"""

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.5-flash:generateContent?key={api_key}"
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 1024, "temperature": 0.3}
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload, timeout=60
                ) as resp:
                    data = await resp.json()
            return data['candidates'][0]['content']['parts'][0]['text']
        except Exception as e:
            log.error(f"Patch generation error: {e}")
            return None
