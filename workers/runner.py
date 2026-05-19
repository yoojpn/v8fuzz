"""
WorkerPool: d8/jscを並列実行してクラッシュを検出
・tmpfsで高速I/O
・スナップショットで起動コスト削減
・タイムアウト管理
・3種類のWorker（探索・狙撃・差分）
"""
import asyncio
import hashlib
import logging
import os
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import List, Optional

log = logging.getLogger('runner')


# ── シングルプロセスで実行（ProcessPoolExecutorから呼ばれる）──

def _run_single(args: dict) -> dict:
    """
    1つのJSケースを実行してクラッシュを検出
    ProcessPoolExecutorから呼ばれるためトップレベル関数
    """
    binary    = args['binary']
    flags     = args['flags']
    js_code   = args['js_code']
    timeout   = args['timeout_ms'] / 1000
    tmpfs_dir = args['tmpfs_dir']
    snapshot  = args.get('snapshot')
    seed_id   = args.get('seed_id', 'unknown')
    worker_type = args.get('worker_type', 'explorer')

    # tmpfsに一時ファイル作成
    path = os.path.join(tmpfs_dir, f"{os.getpid()}_{uuid.uuid4().hex}.js")

    try:
        with open(path, 'w') as f:
            f.write(js_code)

        cmd = [binary] + flags

        if snapshot and os.path.exists(snapshot):
            cmd += [f'--snapshot-blob={snapshot}']

        cmd.append(path)

        env = dict(os.environ)
        env['ASAN_OPTIONS'] = 'halt_on_error=1:symbolize=0'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1'

        start = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 1,
            env=env,
        )
        elapsed = time.time() - start

        crashed = result.returncode not in (0, 1)  # 0=正常, 1=JS例外
        timeout_hit = False

        return {
            'seed_id':     seed_id,
            'crashed':     crashed,
            'timeout':     timeout_hit,
            'returncode':  result.returncode,
            'stderr':      result.stderr.decode('utf-8', errors='replace')[:4096],
            'stdout':      result.stdout.decode('utf-8', errors='replace')[:1024],
            'elapsed':     elapsed,
            'worker_type': worker_type,
            'js_code':     js_code,
        }

    except subprocess.TimeoutExpired:
        return {
            'seed_id':     seed_id,
            'crashed':     False,
            'timeout':     True,
            'returncode':  -1,
            'stderr':      '',
            'stdout':      '',
            'elapsed':     timeout,
            'worker_type': worker_type,
            'js_code':     js_code,
        }
    except Exception as e:
        return {
            'seed_id':  seed_id,
            'crashed':  False,
            'timeout':  False,
            'error':    str(e),
            'elapsed':  0,
            'js_code':  js_code,
        }
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def _run_differ(args: dict) -> Optional[dict]:
    """
    差分型Worker: JIT最適化ON/OFFで実行結果を比較
    答えが違う = バグ候補（クラッシュしないバグを検出）
    """
    # 最適化ONで実行
    args_on = dict(args)
    args_on['flags'] = args['flags'] + ['--opt']
    result_on = _run_single(args_on)

    # 最適化OFFで実行
    args_off = dict(args)
    args_off['flags'] = args['flags'] + ['--no-opt']
    result_off = _run_single(args_off)

    # どちらかがクラッシュ
    if result_on['crashed'] or result_off['crashed']:
        return result_on if result_on['crashed'] else result_off

    # 出力が異なる = バグ候補
    if result_on.get('stdout') != result_off.get('stdout'):
        return {
            **result_on,
            'crashed':        True,
            'differ_bug':     True,
            'output_on':      result_on.get('stdout', ''),
            'output_off':     result_off.get('stdout', ''),
            'worker_type':    'differ',
        }

    return None


class WorkerPool:
    def __init__(self, config: dict, engine: str, corpus):
        self.config   = config
        self.engine   = engine
        self.corpus   = corpus
        self.eng_cfg  = config['engines'][engine]
        self.tmpfs    = config['infra']['tmpfs_dir']
        self.executor = ProcessPoolExecutor(
            max_workers=self.eng_cfg['workers']
        )

        # Worker比率
        wc = config['workers']
        self.explorer_ratio = wc['explorer']
        self.sniper_ratio   = wc['sniper']
        self.differ_ratio   = wc['differ']

        # クラッシュdedup
        self._seen_crashes = set()

        log.info(
            f"WorkerPool[{engine}] initialized: "
            f"{self.eng_cfg['workers']} workers"
        )

    async def run_batch(self, seeds: List[dict]) -> List[dict]:
        """seedのバッチを並列実行してクラッシュを返す"""
        if not seeds:
            return []

        loop = asyncio.get_event_loop()
        tasks = []

        for i, seed in enumerate(seeds):
            # Worker種別を比率で割り当て
            ratio = i / len(seeds)
            if ratio < self.explorer_ratio:
                wtype = 'explorer'
            elif ratio < self.explorer_ratio + self.sniper_ratio:
                wtype = 'sniper'
            else:
                wtype = 'differ'

            # 変異体を生成
            mutants = self._mutate(seed, wtype)

            for mutant in mutants:
                args = {
                    'binary':      self.eng_cfg['binary'],
                    'flags':       self.eng_cfg['flags'],
                    'js_code':     mutant,
                    'timeout_ms':  self.eng_cfg['timeout_ms'],
                    'tmpfs_dir':   self.tmpfs,
                    'snapshot':    self.eng_cfg.get('snapshot'),
                    'seed_id':     seed['id'],
                    'worker_type': wtype,
                }

                if wtype == 'differ':
                    fn = _run_differ
                else:
                    fn = _run_single

                tasks.append(
                    loop.run_in_executor(self.executor, fn, args)
                )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        crashes = []
        for result in results:
            if isinstance(result, Exception):
                continue
            if result and result.get('crashed'):
                crash = self._process_crash(result)
                if crash:
                    crashes.append(crash)

        return crashes

    def _mutate(self, seed: dict, worker_type: str) -> List[str]:
        """
        seedから変異体を生成
        runner.pyはシンプルな変異のみ
        複雑な変異はmutator.pyが担当
        """
        from workers.mutator import Mutator
        mutator = Mutator()

        if worker_type == 'explorer':
            return mutator.explore(seed['code'], count=50)
        elif worker_type == 'sniper':
            return mutator.snipe(seed['code'], seed.get('cve_hint'), count=50)
        else:
            return mutator.differ(seed['code'], count=20)

    def _process_crash(self, result: dict) -> Optional[dict]:
        """クラッシュを処理してdedup"""
        # スタックトレースのトップ5フレームでdedup
        stderr = result.get('stderr', '')
        sig = self._crash_signature(stderr)

        if sig in self._seen_crashes:
            return None  # 重複

        self._seen_crashes.add(sig)

        crash_id = f"CR-{uuid.uuid4().hex[:6].upper()}"
        return {
            'id':          crash_id,
            'engine':      self.engine,
            'seed_id':     result['seed_id'],
            'js_code':     result['js_code'],
            'stderr':      result['stderr'],
            'returncode':  result['returncode'],
            'worker_type': result.get('worker_type', 'unknown'),
            'differ_bug':  result.get('differ_bug', False),
            'timestamp':   time.time(),
            'signature':   sig,
        }

    def _crash_signature(self, stderr: str) -> str:
        """スタックトレースからデdup用シグネチャを生成"""
        lines = stderr.split('\n')
        # V8/JSCのスタックフレームを抽出
        frames = [
            l for l in lines
            if any(x in l for x in [
                'v8::', 'V8::', 'JSC::', 'WebCore::',
                '#0 ', '#1 ', '#2 ', '#3 ', '#4 ',
            ])
        ][:5]

        if not frames:
            # スタックがなければreturncode + stderr先頭で代用
            frames = [stderr[:200]]

        sig = '\n'.join(frames)
        return hashlib.md5(sig.encode()).hexdigest()

    def __del__(self):
        self.executor.shutdown(wait=False)
