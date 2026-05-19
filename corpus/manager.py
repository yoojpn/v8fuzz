"""
CorpusManager: コーパス管理
・品質ゲート（AST多様性・実行可能性）
・間引き（30日クラッシュなし→削除）
・カバレッジ新規性チェック
"""
import hashlib
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

log = logging.getLogger('corpus')


class CorpusManager:
    def __init__(self, config: dict, engine: str):
        self.config  = config
        self.engine  = engine
        self.db_path = config['infra']['db_path']
        self.cfg     = config['corpus']
        self._init_db()

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as db:
            db.execute(f"""
                CREATE TABLE IF NOT EXISTS corpus_{self.engine} (
                    id          TEXT PRIMARY KEY,
                    code        TEXT NOT NULL,
                    source      TEXT,
                    ast_hash    TEXT,
                    coverage    REAL DEFAULT 0.0,
                    crashes     INTEGER DEFAULT 0,
                    pulls       INTEGER DEFAULT 0,
                    created_at  REAL,
                    last_used   REAL,
                    cve_hint    TEXT
                )
            """)

    async def add_seeds(self, seeds: List[dict]) -> int:
        """品質ゲートを通過したseedをコーパスに追加"""
        added = 0
        current_size = self._size()

        for seed in seeds:
            # サイズ上限チェック
            if current_size >= self.cfg['max_size']:
                log.warning(f"Corpus full ({current_size}), retiring old seeds")
                self._retire_old_seeds()
                current_size = self._size()

            # 品質ゲート
            if not self._passes_quality_gate(seed):
                continue

            # DB保存
            try:
                with sqlite3.connect(self.db_path) as db:
                    db.execute(f"""
                        INSERT OR IGNORE INTO corpus_{self.engine}
                            (id, code, source, ast_hash, created_at, last_used, cve_hint)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        seed['id'],
                        seed['code'],
                        seed.get('source', 'unknown'),
                        self._ast_hash(seed['code']),
                        seed.get('created', time.time()),
                        time.time(),
                        seed.get('cve_hint'),
                    ))
                added += 1
                current_size += 1
            except Exception as e:
                log.warning(f"Corpus add error: {e}")

        return added

    async def get_all(self) -> List[dict]:
        """全seedを取得"""
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute(f"""
                SELECT id, code, cve_hint, coverage, crashes
                FROM corpus_{self.engine}
                ORDER BY crashes DESC, coverage DESC
            """).fetchall()

        return [
            {
                'id':       r[0],
                'code':     r[1],
                'cve_hint': r[2],
                'coverage': r[3],
                'crashes':  r[4],
            }
            for r in rows
        ]

    def record_crash(self, seed_id: str):
        """クラッシュを記録"""
        with sqlite3.connect(self.db_path) as db:
            db.execute(f"""
                UPDATE corpus_{self.engine}
                SET crashes = crashes + 1,
                    last_used = ?
                WHERE id = ?
            """, (time.time(), seed_id))

    def record_coverage(self, seed_id: str, coverage: float):
        """カバレッジを記録"""
        with sqlite3.connect(self.db_path) as db:
            db.execute(f"""
                UPDATE corpus_{self.engine}
                SET coverage = MAX(coverage, ?),
                    last_used = ?
                WHERE id = ?
            """, (coverage, time.time(), seed_id))

    def _passes_quality_gate(self, seed: dict) -> bool:
        """品質ゲート: 以下を全部パスしたseedだけ採用"""
        code = seed.get('code', '')

        # 1. 最小長チェック
        if len(code) < 20:
            return False

        # 2. 実行可能性チェック（簡易）
        if not self._is_valid_js(code):
            return False

        # 3. AST多様性チェック（類似seedを弾く）
        ast_h = self._ast_hash(code)
        if self._similar_exists(ast_h):
            return False

        return True

    def _is_valid_js(self, code: str) -> bool:
        """基本的なJS構文チェック（括弧のバランスなど）"""
        # 簡易チェック: 括弧・波括弧のバランス
        try:
            opens  = code.count('(') + code.count('{') + code.count('[')
            closes = code.count(')') + code.count('}') + code.count(']')
            # 多少のアンバランスは許容（意図的なバグ誘発JSもある）
            if abs(opens - closes) > 20:
                return False
            return True
        except Exception:
            return False

    def _ast_hash(self, code: str) -> str:
        """
        AST構造のハッシュを計算（多様性チェック用）
        完全なASTパースは重いので、構造的な特徴を抽出
        """
        import re

        # 数値・文字列リテラルを正規化
        normalized = re.sub(r'\b\d+\b', 'N', code)
        normalized = re.sub(r'"[^"]*"', 'S', normalized)
        normalized = re.sub(r"'[^']*'", 'S', normalized)
        normalized = re.sub(r'`[^`]*`', 'S', normalized)

        # 変数名を正規化
        normalized = re.sub(r'\b[a-z_][a-z0-9_]*\b', 'V', normalized)

        # 空白を正規化
        normalized = re.sub(r'\s+', ' ', normalized).strip()

        return hashlib.md5(normalized.encode()).hexdigest()[:16]

    def _similar_exists(self, ast_hash: str) -> bool:
        """類似seedが既に存在するか（完全一致のみチェック）"""
        with sqlite3.connect(self.db_path) as db:
            row = db.execute(f"""
                SELECT 1 FROM corpus_{self.engine}
                WHERE ast_hash = ?
                LIMIT 1
            """, (ast_hash,)).fetchone()
        return row is not None

    def _retire_old_seeds(self):
        """
        間引き: 古くて役立たないseedを削除
        30日間クラッシュなし + カバレッジ低 → 削除
        """
        cutoff = time.time() - self.cfg['retire_after_days'] * 86400
        with sqlite3.connect(self.db_path) as db:
            db.execute(f"""
                DELETE FROM corpus_{self.engine}
                WHERE last_used < ?
                  AND crashes = 0
                  AND coverage < ?
            """, (cutoff, self.cfg['min_coverage_gain']))

        log.info(f"Corpus [{self.engine}] retired old seeds")

    def _size(self) -> int:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute(
                f"SELECT COUNT(*) FROM corpus_{self.engine}"
            ).fetchone()
        return row[0] if row else 0

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute(f"""
                SELECT
                    COUNT(*) as total,
                    SUM(crashes) as total_crashes,
                    AVG(coverage) as avg_coverage,
                    MAX(crashes) as max_crashes
                FROM corpus_{self.engine}
            """).fetchone()
        return {
            'total':         row[0],
            'total_crashes': row[1] or 0,
            'avg_coverage':  row[2] or 0.0,
            'max_crashes':   row[3] or 0,
        }
