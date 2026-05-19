"""
T-Scheduler: 多腕バンディット（UCB1）によるseed選択
「当たりやすいseed」を自動的に優先する
"""
import math
import time
import sqlite3
from pathlib import Path
from typing import List


class Scheduler:
    def __init__(self, config: dict):
        self.config = config
        self.exploration = config['scheduler']['exploration_factor']
        self.db_path = config['infra']['db_path']
        self._init_db()

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS seed_stats (
                    seed_id     TEXT PRIMARY KEY,
                    engine      TEXT,
                    pulls       INTEGER DEFAULT 0,
                    crashes     INTEGER DEFAULT 0,
                    coverage    REAL    DEFAULT 0.0,
                    last_used   REAL    DEFAULT 0.0,
                    created_at  REAL    DEFAULT 0.0
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS global_stats (
                    engine      TEXT PRIMARY KEY,
                    total_pulls INTEGER DEFAULT 0
                )
            """)

    def ucb1_score(self, pulls: int, crashes: int,
                   coverage: float, total_pulls: int) -> float:
        """
        UCB1スコア計算
        報酬 = クラッシュ率 × 0.7 + カバレッジ寄与 × 0.3
        探索ボーナス = sqrt(2 * ln(total) / pulls)
        """
        if pulls == 0:
            return float('inf')  # 未試行は最優先

        reward = (crashes / pulls) * 0.7 + coverage * 0.3
        explore = self.exploration * math.sqrt(
            math.log(max(total_pulls, 1)) / pulls
        )
        return reward + explore

    async def select(self, corpus, count: int = 1000) -> List[dict]:
        """コーパスからcount個のseedをUCB1で選択"""
        seeds = await corpus.get_all()
        if not seeds:
            return []

        with sqlite3.connect(self.db_path) as db:
            row = db.execute(
                "SELECT total_pulls FROM global_stats WHERE engine=?",
                (corpus.engine,)
            ).fetchone()
            total_pulls = row[0] if row else 0

        # UCB1スコアで全seedをランク付け
        scored = []
        for seed in seeds:
            stats = self._get_stats(seed['id'], corpus.engine)
            score = self.ucb1_score(
                stats['pulls'],
                stats['crashes'],
                stats['coverage'],
                total_pulls
            )
            scored.append((score, seed))

        scored.sort(key=lambda x: x[0], reverse=True)
        selected = [s for _, s in scored[:count]]

        # 選択したseedの統計を更新
        self._record_pulls(
            [s['id'] for s in selected],
            corpus.engine
        )

        return selected

    def record_crash(self, seed_id: str, engine: str):
        """クラッシュが出たseedの統計を更新"""
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                UPDATE seed_stats
                SET crashes = crashes + 1
                WHERE seed_id=? AND engine=?
            """, (seed_id, engine))

    def record_coverage(self, seed_id: str, engine: str,
                        coverage_gain: float):
        """カバレッジ貢献を記録"""
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                UPDATE seed_stats
                SET coverage = MAX(coverage, ?)
                WHERE seed_id=? AND engine=?
            """, (coverage_gain, seed_id, engine))

    def _get_stats(self, seed_id: str, engine: str) -> dict:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("""
                SELECT pulls, crashes, coverage
                FROM seed_stats
                WHERE seed_id=? AND engine=?
            """, (seed_id, engine)).fetchone()

        if row:
            return {'pulls': row[0], 'crashes': row[1], 'coverage': row[2]}
        return {'pulls': 0, 'crashes': 0, 'coverage': 0.0}

    def _record_pulls(self, seed_ids: List[str], engine: str):
        now = time.time()
        with sqlite3.connect(self.db_path) as db:
            for sid in seed_ids:
                db.execute("""
                    INSERT INTO seed_stats
                        (seed_id, engine, pulls, last_used, created_at)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT(seed_id) DO UPDATE SET
                        pulls = pulls + 1,
                        last_used = ?
                """, (sid, engine, now, now, now))

            db.execute("""
                INSERT INTO global_stats (engine, total_pulls)
                VALUES (?, ?)
                ON CONFLICT(engine) DO UPDATE SET
                    total_pulls = total_pulls + ?
            """, (engine, len(seed_ids), len(seed_ids)))
