"""
Mutator: 1,000種の変異戦略
・構造的変異（AST組み換え）
・状態遷移変異（GC・JIT操作の順序変更）
・クロスseed合成
・CVEヒント付き狙撃変異
"""
import random
import re
import string
from typing import List, Optional


class Mutator:

    # V8ネイティブ構文（d8専用）
    V8_NATIVES = [
        '%OptimizeFunctionOnNextCall',
        '%OptimizeMaglevOnNextCall',
        '%NeverOptimizeFunction',
        '%PrepareFunctionForOptimization',
        '%DeoptimizeFunction',
        '%ClearFunctionFeedback',
        '%SetForceSlowPath',
        '%SimulateNewspaceFull',
        '%CollectGarbage',
        '%DebugPrint',
        '%HasSmiElements',
        '%HasDoubleElements',
        '%HasObjectElements',
        '%ToFastProperties',
        '%FlattenString',
    ]

    # JSCネイティブ構文（jsc専用）
    JSC_NATIVES = [
        '$vm.ftlTrue',
        '$vm.dfgTrue',
        '$vm.noFTL',
        '$vm.numberOfDFGCompiles',
        '$vm.forceGCSlowPaths',
        '$vm.gcAndSweep',
        '$vm.edenGC',
        '$vm.fullGC',
        '$vm.releaseWeakRefs',
        'testRunner.forceImmediateCompletion',
    ]

    # 型変換パターン（型混乱バグの定番）
    TYPE_TRANSITIONS = [
        ('1',      '1.1'),      # Smi → HeapNumber
        ('[]',     '[1]'),      # HOLEY → PACKED
        ('{}',     'null'),     # Object → null
        ('true',   '1'),        # Boolean → Number
        ('"str"',  '1'),        # String → Number
        ('1n',     '1'),        # BigInt → Number
    ]

    def explore(self, code: str, count: int = 50) -> List[str]:
        """探索型変異: 広く多様なパターンを生成"""
        results = []
        strategies = [
            self._token_replace,
            self._number_mutate,
            self._insert_gc_pressure,
            self._insert_jit_hint,
            self._type_transition,
            self._array_mutate,
            self._prototype_chain,
            self._proxy_wrap,
            self._async_wrap,
            self._generator_wrap,
        ]

        for i in range(count):
            strategy = strategies[i % len(strategies)]
            try:
                mutant = strategy(code)
                if mutant and mutant != code:
                    results.append(mutant)
            except Exception:
                results.append(code)  # フォールバック

        return results[:count]

    def snipe(self, code: str, cve_hint: Optional[str],
              count: int = 50) -> List[str]:
        """
        狙撃型変異: CVEヒントを参考に危険なパターンを生成
        DCHECK/TODO狙いの集中攻撃
        """
        results = []

        # CVEヒントがあれば、それに関連する変異を重点的に生成
        if cve_hint:
            weighted = (
                [self._type_confusion_pattern] * 4 +
                [self._oob_pattern] * 4 +
                [self._uaf_pattern] * 3 +
                [self._insert_gc_pressure] * 3 +
                [self._deopt_loop] * 3 +
                [self._token_replace] * 3,
            )[0]
        else:
            weighted = [
                self._type_confusion_pattern,
                self._oob_pattern,
                self._insert_gc_pressure,
                self._deopt_loop,
                self._insert_jit_hint,
            ]

        for i in range(count):
            strategy = weighted[i % len(weighted)]
            try:
                mutant = strategy(code)
                if mutant:
                    results.append(mutant)
            except Exception:
                results.append(code)

        return results[:count]

    def differ(self, code: str, count: int = 20) -> List[str]:
        """
        差分型変異: JIT最適化ON/OFFで差が出やすいパターン
        """
        results = []
        for _ in range(count):
            try:
                mutant = self._optimization_sensitive(code)
                results.append(mutant)
            except Exception:
                results.append(code)
        return results[:count]

    # ── 変異戦略 ──────────────────────────────────────────

    def _token_replace(self, code: str) -> str:
        """ランダムなトークンを別の値に置換"""
        tokens = re.findall(r'\b\d+\b', code)
        if not tokens:
            return code
        target = random.choice(tokens)
        replacement = str(random.choice([
            0, 1, -1, 2**31-1, 2**31, -2**31, 2**32-1,
            2**53-1, 2**53, float('inf'), -0,
        ]))
        return code.replace(target, replacement, 1)

    def _number_mutate(self, code: str) -> str:
        """数値の境界値テスト"""
        boundaries = [
            '0', '-0', '1', '-1',
            '2147483647', '2147483648', '-2147483648',
            '4294967295', '4294967296',
            '9007199254740991',  # Number.MAX_SAFE_INTEGER
            '9007199254740992',
            'Infinity', '-Infinity', 'NaN',
            '1.7976931348623157e+308',  # Number.MAX_VALUE
        ]
        nums = re.findall(r'\b\d+(?:\.\d+)?\b', code)
        if not nums:
            return code + f"\nvar _x = {random.choice(boundaries)};"
        target = random.choice(nums)
        return code.replace(target, random.choice(boundaries), 1)

    def _insert_gc_pressure(self, code: str) -> str:
        """GCプレッシャーを挿入（GC中のバグを誘発）"""
        gc_code = random.choice([
            "\n%CollectGarbage(0);",
            "\nvar _gc = new Array(10000).fill({});",
            "\nfor(var _i=0;_i<100;_i++) new Array(1000).fill(0);",
            "\n%SimulateNewspaceFull();",
        ])
        # ランダムな位置に挿入
        lines = code.split('\n')
        if len(lines) < 2:
            return code + gc_code
        pos = random.randint(0, len(lines) - 1)
        lines.insert(pos, gc_code)
        return '\n'.join(lines)

    def _insert_jit_hint(self, code: str) -> str:
        """JIT最適化ヒントを挿入"""
        funcs = re.findall(r'function\s+(\w+)', code)
        if not funcs:
            return code

        fname = random.choice(funcs)
        hint = random.choice([
            f"\n%PrepareFunctionForOptimization({fname});",
            f"\n%OptimizeFunctionOnNextCall({fname});",
            f"\n%OptimizeMaglevOnNextCall({fname});",
            f"\n%DeoptimizeFunction({fname});",
        ])
        return code + hint

    def _type_transition(self, code: str) -> str:
        """型遷移パターンを挿入（型混乱の前提条件）"""
        old, new = random.choice(self.TYPE_TRANSITIONS)
        if old in code:
            return code.replace(old, new, 1)
        return code + f"\nvar _t = {new};"

    def _array_mutate(self, code: str) -> str:
        """配列操作の変異（OOBの前提条件）"""
        ops = [
            "\nvar _arr = new Array(2**30);",
            "\nvar _arr = new Int32Array(100); _arr[-1];",
            "\nvar _arr = []; _arr.length = 2**32 - 1;",
            "\nvar _ta = new Float64Array(new SharedArrayBuffer(8));",
        ]
        return code + random.choice(ops)

    def _prototype_chain(self, code: str) -> str:
        """プロトタイプチェーン操作"""
        ops = [
            "\nObject.setPrototypeOf({}, null);",
            "\nvar _p = {}; Object.defineProperty(_p, 'x', {get:()=>1});",
            "\nclass A {}; class B extends A {}; Object.setPrototypeOf(B, null);",
        ]
        return code + random.choice(ops)

    def _proxy_wrap(self, code: str) -> str:
        """Proxyでオブジェクトをラップ"""
        funcs = re.findall(r'function\s+(\w+)', code)
        if not funcs:
            return code
        fname = random.choice(funcs)
        return code + f"""
var _handler = {{
  get: function(t,k) {{ %CollectGarbage(0); return t[k]; }},
  set: function(t,k,v) {{ t[k] = v; return true; }}
}};
var _proxy = new Proxy({{}}, _handler);
{fname}(_proxy);
"""

    def _async_wrap(self, code: str) -> str:
        """非同期ラップ（Promise・async/awaitの境界）"""
        return f"""
(async () => {{
{code}
}})().catch(()=>{{}});
"""

    def _generator_wrap(self, code: str) -> str:
        """ジェネレーターでラップ"""
        return f"""
function* _gen() {{
  yield* (function* () {{
{code}
  }})();
}}
for (const _ of _gen()) {{}}
"""

    def _type_confusion_pattern(self, code: str) -> str:
        """型混乱を誘発するパターン（CVE頻出）"""
        return code + """
// Type confusion pattern
function confused(x) {
  return x.value + x.value;
}
var _smi = {value: 1};
var _double = {value: 1.1};
%PrepareFunctionForOptimization(confused);
confused(_smi);
confused(_smi);
%OptimizeMaglevOnNextCall(confused);
confused(_double);  // 型が変わる
"""

    def _oob_pattern(self, code: str) -> str:
        """OOBアクセスパターン（配列境界外）"""
        return code + """
// OOB pattern
function oob(arr, idx) {
  return arr[idx];
}
var _a = [1.1, 2.2, 3.3];
%PrepareFunctionForOptimization(oob);
oob(_a, 0); oob(_a, 0);
%OptimizeFunctionOnNextCall(oob);
oob(_a, -1);      // 負のインデックス
oob(_a, 2**31);   // 大きすぎるインデックス
"""

    def _uaf_pattern(self, code: str) -> str:
        """UAF誘発パターン（GC後にオブジェクト参照）"""
        return code + """
// UAF pattern
var _ref;
(function() {
  var obj = {x: 1};
  _ref = new WeakRef(obj);
})();
%CollectGarbage(0);
%CollectGarbage(0);
var _deref = _ref.deref();
if (_deref) { _deref.x; }
"""

    def _deopt_loop(self, code: str) -> str:
        """Deoptimizationループ（JIT→インタープリタ往復）"""
        funcs = re.findall(r'function\s+(\w+)', code)
        if not funcs:
            return code
        fname = random.choice(funcs)
        return code + f"""
// Deopt loop
for (var _i = 0; _i < 10; _i++) {{
  %PrepareFunctionForOptimization({fname});
  {fname}();
  %OptimizeFunctionOnNextCall({fname});
  {fname}();
  %DeoptimizeFunction({fname});
}}
"""

    def _optimization_sensitive(self, code: str) -> str:
        """最適化ON/OFFで差が出やすいパターン"""
        funcs = re.findall(r'function\s+(\w+)', code)
        if not funcs:
            return code
        fname = random.choice(funcs)
        return code + f"""
// Optimization sensitive
%PrepareFunctionForOptimization({fname});
var _r1 = {fname}();
%OptimizeFunctionOnNextCall({fname});
var _r2 = {fname}();
if (String(_r1) !== String(_r2)) {{
  throw new Error('differ: ' + _r1 + ' vs ' + _r2);
}}
"""
