"""
v8fuzz メインコントローラー
全コンポーネントを起動・管理する
"""
import asyncio
import logging
import signal
import sys
from pathlib import Path

import yaml

from scheduler import Scheduler
from commit_watcher import CommitWatcher
sys.path.append(str(Path(__file__).parent.parent))
from workers.runner import WorkerPool
from corpus.manager import CorpusManager
from corpus.generator import SeedGenerator
from triage.analyzer import CrashAnalyzer
from triage.reporter import VRPReporter

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/opt/v8fuzz/logs/service.log'),
        logging.FileHandler('/opt/v8fuzz/logs/controller.log'),
    ]
)
log = logging.getLogger('controller')


def load_config() -> dict:
    path = Path(__file__).parent.parent / 'config' / 'config.yaml'
    with open(path) as f:
        return yaml.safe_load(f)


class V8FuzzController:
    def __init__(self, config: dict):
        self.config = config
        self.running = False

        # コンポーネント初期化
        self.corpus_v8  = CorpusManager(config, engine='v8')
        self.corpus_jsc = CorpusManager(config, engine='jsc')

        self.generator  = SeedGenerator(config)
        self.scheduler  = Scheduler(config)

        self.workers_v8  = WorkerPool(config, engine='v8',
                                      corpus=self.corpus_v8)
        self.workers_jsc = WorkerPool(config, engine='jsc',
                                      corpus=self.corpus_jsc)

        self.analyzer   = CrashAnalyzer(config)
        self.reporter   = VRPReporter(config)
        self.watcher    = CommitWatcher(config)

    async def run(self):
        self.running = True
        log.info("v8fuzz starting up...")

        # tmpfs マウント確認
        self._check_tmpfs()

        # 並列タスク起動
        tasks = [
            asyncio.create_task(self._seed_generation_loop()),
            asyncio.create_task(self._v8_fuzz_loop()),
            asyncio.create_task(self._jsc_fuzz_loop()),
            asyncio.create_task(self._triage_loop()),
            asyncio.create_task(self._commit_watch_loop()),
            asyncio.create_task(self._daily_summary_loop()),
        ]

        log.info("All workers started. Running...")

        # 10ヶ月自動停止タスク
        tasks.append(asyncio.create_task(self._auto_stop_loop()))

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            log.info("Shutting down...")
        finally:
            self.running = False

    async def _auto_stop_loop(self):
        """10ヶ月後に自動停止（課金防止）"""
        import subprocess
        # 10ヶ月 = 300日
        stop_after_seconds = 300 * 24 * 3600
        log.info(f"Auto-stop scheduled in 300 days")
        await asyncio.sleep(stop_after_seconds)

        log.info("=== 10ヶ月経過・自動停止します ===")

        # 停止前に最終サマリーメールを送信
        try:
            await self.reporter.send_daily_summary()
        except Exception:
            pass

        # systemdサービスを停止してシャットダウン
        # ※Dropletは削除しない（データ保全のため）
        import subprocess
        subprocess.run(['systemctl', 'stop', 'v8fuzz'], check=False)
        subprocess.run(['shutdown', '-h', 'now'], check=False)

    def _check_tmpfs(self):
        """tmpfsマウント確認・未マウントなら警告"""
        tmpfs = Path(self.config['infra']['tmpfs_dir'])
        tmpfs.mkdir(parents=True, exist_ok=True)
        log.info(f"tmpfs dir: {tmpfs}")

    async def _seed_generation_loop(self):
        """毎日AIでseedを生成する"""
        while self.running:
            try:
                log.info("Starting daily seed generation...")
                seeds_v8  = await self.generator.generate_batch(engine='v8')
                seeds_jsc = await self.generator.generate_batch(engine='jsc')

                # 品質ゲートを通過したseedだけ追加
                added_v8  = await self.corpus_v8.add_seeds(seeds_v8)
                added_jsc = await self.corpus_jsc.add_seeds(seeds_jsc)

                log.info(f"Seeds added: V8={added_v8}, JSC={added_jsc}")

                # 24時間待機
                await asyncio.sleep(86400)

            except Exception as e:
                log.error(f"Seed generation error: {e}")
                await asyncio.sleep(3600)

    async def _v8_fuzz_loop(self):
        """V8 fuzz実行ループ"""
        while self.running:
            try:
                # T-Schedulerがseedを選択
                seeds = await self.scheduler.select(
                    self.corpus_v8, count=1000
                )
                crashes = await self.workers_v8.run_batch(seeds)

                if crashes:
                    log.info(f"V8 crashes: {len(crashes)}")
                    for crash in crashes:
                        await self.analyzer.queue(crash, engine='v8')

            except Exception as e:
                log.error(f"V8 fuzz error: {e}")
                await asyncio.sleep(10)

    async def _jsc_fuzz_loop(self):
        """JSC fuzz実行ループ"""
        while self.running:
            try:
                seeds = await self.scheduler.select(
                    self.corpus_jsc, count=1000
                )
                crashes = await self.workers_jsc.run_batch(seeds)

                if crashes:
                    log.info(f"JSC crashes: {len(crashes)}")
                    for crash in crashes:
                        await self.analyzer.queue(crash, engine='jsc')

            except Exception as e:
                log.error(f"JSC fuzz error: {e}")
                await asyncio.sleep(10)

    async def _triage_loop(self):
        """クラッシュ解析・VRP判定ループ"""
        while self.running:
            try:
                crash = await self.analyzer.dequeue()
                if crash is None:
                    await asyncio.sleep(5)
                    continue

                result = await self.analyzer.analyze(crash)

                if result['vrp_eligible']:
                    log.info(
                        f"VRP candidate: {crash['id']} "
                        f"CVSS={result['cvss']} "
                        f"est=${result['estimated_reward_min']}"
                        f"~${result['estimated_reward_max']}"
                    )
                    await self.reporter.handle(crash, result)

            except Exception as e:
                log.error(f"Triage error: {e}")
                await asyncio.sleep(5)

    async def _commit_watch_loop(self):
        """新コミット監視ループ"""
        while self.running:
            try:
                new_commits = await self.watcher.check()
                for commit in new_commits:
                    log.info(
                        f"New commit detected: {commit['hash'][:8]} "
                        f"- {commit['message'][:60]}"
                    )
                    # 危険なコミットにはseed生成を優先
                    if commit['risk_score'] >= 7.0:
                        await self.generator.generate_for_commit(commit)

                await asyncio.sleep(
                    self.config['commit_watcher']['check_interval']
                )
            except Exception as e:
                log.error(f"Commit watcher error: {e}")
                await asyncio.sleep(3600)

    async def _daily_summary_loop(self):
        """毎朝9時に日次サマリーを送信"""
        import datetime
        while self.running:
            try:
                now = datetime.datetime.now()
                # 次の9時まで待つ
                next_9 = now.replace(
                    hour=9, minute=0, second=0, microsecond=0
                )
                if now >= next_9:
                    next_9 += datetime.timedelta(days=1)

                wait = (next_9 - now).total_seconds()
                await asyncio.sleep(wait)

                await self.reporter.send_daily_summary()

            except Exception as e:
                log.error(f"Daily summary error: {e}")
                await asyncio.sleep(3600)


def main():
    config = load_config()
    controller = V8FuzzController(config)

    loop = asyncio.get_event_loop()

    def shutdown(sig, frame):
        log.info(f"Signal {sig} received, shutting down...")
        for task in asyncio.all_tasks(loop):
            task.cancel()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    loop.run_until_complete(controller.run())


if __name__ == '__main__':
    main()
