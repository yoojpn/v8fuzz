"""
CommitWatcher: V8/JSCの新コミットを監視
・黄金ゾーン（8〜30日）のコミットを狙う
・Gerritのコードレビューコメントから危険箇所を抽出
"""
import asyncio
import hashlib
import logging
import time
from datetime import datetime, timedelta
from typing import List, Optional
import sqlite3

import aiohttp

log = logging.getLogger('commit_watcher')


class CommitWatcher:
    def __init__(self, config: dict):
        self.config = config
        self.db_path = config['infra']['db_path']
        self.gerrit_cfg = config.get('gerrit', {})
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS seen_commits (
                    hash        TEXT PRIMARY KEY,
                    engine      TEXT,
                    message     TEXT,
                    author      TEXT,
                    timestamp   REAL,
                    risk_score  REAL DEFAULT 0.0,
                    processed   INTEGER DEFAULT 0
                )
            """)

    async def check(self) -> List[dict]:
        """新コミットをチェックして返す"""
        new_commits = []

        v8_commits  = await self._fetch_v8_commits()
        jsc_commits = await self._fetch_jsc_commits()

        for commit in v8_commits + jsc_commits:
            if not self._seen(commit['hash']):
                commit['risk_score'] = self._score_commit(commit)
                self._save(commit)
                new_commits.append(commit)
                log.info(
                    f"New {commit['engine']} commit: "
                    f"{commit['hash'][:8]} risk={commit['risk_score']:.1f}"
                )

        return new_commits

    async def _fetch_v8_commits(self) -> List[dict]:
        """V8の最新コミットをChromium Gitから取得"""
        url = (
            "https://chromium.googlesource.com/v8/v8/+log/main"
            "?format=JSON&n=50"
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    text = await resp.text()
                    # Googlesourceは先頭に )]}' がある
                    import json
                    data = json.loads(text.lstrip(")]}'"))
                    commits = []
                    for c in data.get('log', []):
                        commits.append({
                            'hash':    c['commit'],
                            'message': c['message'][:200],
                            'author':  c.get('author', {}).get('email', ''),
                            'timestamp': time.time(),
                            'engine':  'v8',
                            'files':   [],
                        })
                    return commits
        except Exception as e:
            log.error(f"V8 commit fetch error: {e}")
            return []

    async def _fetch_jsc_commits(self) -> List[dict]:
        """JSCの最新コミットをGitHub APIから取得"""
        url = (
            "https://api.github.com/repos/WebKit/WebKit"
            "/commits?path=Source/JavaScriptCore&per_page=50"
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers={'Accept': 'application/vnd.github.v3+json'},
                    timeout=30
                ) as resp:
                    data = await resp.json()
                    commits = []
                    for c in data:
                        commits.append({
                            'hash':    c['sha'],
                            'message': c['commit']['message'][:200],
                            'author':  c['commit']['author']['email'],
                            'timestamp': time.time(),
                            'engine':  'jsc',
                            'files':   [],
                        })
                    return commits
        except Exception as e:
            log.error(f"JSC commit fetch error: {e}")
            return []

    async def get_gerrit_comments(self, change_id: str) -> List[str]:
        """
        Gerritのコードレビューコメントを取得
        「dangerous」「edge case」「TODO」などを含むコメントを抽出
        """
        if not self.gerrit_cfg.get('enabled'):
            return []

        url = (
            f"{self.gerrit_cfg['url']}/changes/{change_id}"
            f"/comments?format=JSON"
        )
        keywords = self.gerrit_cfg.get('keywords', [])

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    text = await resp.text()
                    import json
                    data = json.loads(text.lstrip(")]}'"))

            dangerous_comments = []
            for file_path, comments in data.items():
                for comment in comments:
                    msg = comment.get('message', '').lower()
                    if any(kw.lower() in msg for kw in keywords):
                        dangerous_comments.append(
                            f"{file_path}: {comment['message']}"
                        )
            return dangerous_comments

        except Exception as e:
            log.error(f"Gerrit fetch error: {e}")
            return []

    def _score_commit(self, commit: dict) -> float:
        """
        コミットの危険度スコアを計算（0〜10）
        危険キーワード・ファイル名・コミットメッセージから推定
        """
        score = 5.0  # ベーススコア
        msg = commit['message'].lower()

        # 危険キーワード（メッセージ）
        danger_keywords = {
            'fix': +1.0,         # バグ修正 = 関連バグある可能性
            'crash': +2.0,
            'memory': +1.5,
            'overflow': +2.0,
            'type': +1.0,
            'optimize': +1.5,    # 最適化 = JIT変更
            'maglev': +2.0,
            'turbofan': +1.5,
            'wasm': +1.5,
            'jit': +2.0,
            'gc': +1.5,
            'security': +3.0,
            'vulnerable': +3.0,
            'oob': +3.0,
            'use after': +3.0,
            'temporal': +2.0,    # 新仕様
            'experimental': -1.0, # 実験的 = VRP対象外リスク
        }

        for kw, delta in danger_keywords.items():
            if kw in msg:
                score += delta

        # ファイルパス（危険なコンポーネント）
        danger_files = [
            'maglev', 'turbofan', 'wasm', 'heap', 'gc',
            'compiler', 'interpreter', 'temporal', 'proxy'
        ]
        for f in commit.get('files', []):
            if any(d in f.lower() for d in danger_files):
                score += 1.0

        return min(max(score, 0.0), 10.0)

    def _seen(self, hash: str) -> bool:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute(
                "SELECT 1 FROM seen_commits WHERE hash=?", (hash,)
            ).fetchone()
        return row is not None

    def _save(self, commit: dict):
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                INSERT OR IGNORE INTO seen_commits
                    (hash, engine, message, author, timestamp, risk_score)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                commit['hash'],
                commit['engine'],
                commit['message'],
                commit['author'],
                commit['timestamp'],
                commit['risk_score'],
            ))

    def get_golden_zone_commits(self, engine: str) -> List[dict]:
        """
        黄金ゾーン（8〜30日前）のコミットを取得
        OSS-Fuzzがまだ薄く・VRP対象になるゾーン
        """
        cfg = self.config['commit_watcher']['golden_zone_days']
        now = time.time()
        min_age = now - cfg['max'] * 86400
        max_age = now - cfg['min'] * 86400

        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("""
                SELECT hash, message, risk_score
                FROM seen_commits
                WHERE engine=?
                  AND timestamp BETWEEN ? AND ?
                ORDER BY risk_score DESC
            """, (engine, min_age, max_age)).fetchall()

        return [
            {'hash': r[0], 'message': r[1], 'risk_score': r[2]}
            for r in rows
        ]
