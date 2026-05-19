# v8fuzz

AI-driven fuzzer for V8 (Google) and JavaScriptCore (Apple).

## Architecture

```
v8fuzz/
├── controller/        # メインオーケストレーター
│   ├── main.py        # エントリーポイント・全体制御
│   ├── scheduler.py   # T-Scheduler（多腕バンディット）
│   └── commit_watcher.py  # 新コミット監視
├── workers/           # fuzz実行エンジン
│   ├── runner.py      # d8/jsc並列実行
│   ├── mutator.py     # 変異エンジン（1,000種）
│   └── coverage.py    # カバレッジ計測
├── corpus/            # コーパス管理
│   ├── manager.py     # 品質ゲート・間引き
│   └── generator.py   # SeedMind式ジェネレーター
├── triage/            # クラッシュ解析
│   ├── analyzer.py    # Gemini VRP判定
│   ├── minimizer.py   # Delta debugging最小化
│   ├── bisect.py      # 導入コミット特定
│   └── reporter.py    # VRPレポート自動生成
├── webui/             # Cloudflare Pages用フロントエンド
│   └── src/
├── scripts/           # セットアップスクリプト
│   ├── setup_do.sh    # DigitalOcean初期設定
│   ├── build_v8.sh    # V8ビルド
│   └── build_jsc.sh   # JSCビルド
├── config/
│   └── config.yaml    # 全設定
└── docker-compose.yml # ローカル開発用
```

## Quick Start

```bash
# 1. 設定ファイルを編集
cp config/config.yaml.example config/config.yaml
vim config/config.yaml  # APIキーなどを設定

# 2. DigitalOcean Droplet上でセットアップ
bash scripts/setup_do.sh

# 3. V8をビルド
bash scripts/build_v8.sh

# 4. 起動
python controller/main.py
```

## Cost

- DigitalOcean g-2: $15/月（GitHub Studentsクレジット）
- Azure F2s v2: $61/月（GitHub Studentsクレジット）
- Gemini API: 無料枠（500 req/日 × 2アカウント）
- Cloudflare Pages: 無料
- Resend: 無料（3,000通/月）
- **合計: $0/月**

## Expected Results

- 実行数: 1億回/日（V8） + 1億回/日（JSC）
- seed: 10,000個/日（Gemini生成）
- 期待採用数: 年5〜15件
- 期待報奨金: $30,000〜$100,000/年（中立シナリオ）
