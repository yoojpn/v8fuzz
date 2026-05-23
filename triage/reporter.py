"""
VRPReporter: クラッシュ → VRPレポート自動生成 → メール通知
・Gmail SMTPでメール送信（Resend不要）
・CVSS 8.0以上は即時通知
・それ以外は日次サマリー
・VRPレポートのMarkdown草稿を自動生成
"""
import asyncio
import json
import logging
import smtplib
import sqlite3
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import aiohttp

from triage.minimizer import Minimizer, Bisector, PatchGenerator

log = logging.getLogger('reporter')


class VRPReporter:
    def __init__(self, config: dict):
        self.config    = config
        self.notify    = config['notification']
        self.triage    = config['triage']
        self.db_path   = config['infra']['db_path']
        self._daily_queue = []

    async def handle(self, crash: dict, analysis: dict):
        """クラッシュを受け取り、最小化→レポート生成→通知"""
        engine = crash.get('engine', 'v8')

        # 1. 最小化
        if self.triage.get('auto_minimize') and crash.get('js_code'):
            log.info(f"Minimizing {crash['id']}...")
            minimizer = Minimizer(self.config, engine)
            minimized = await asyncio.get_event_loop().run_in_executor(
                None, minimizer.minimize, crash['js_code']
            )
            crash['minimized_code'] = minimized
            self._save_minimized(crash['id'], minimized)

        # 2. Bisect
        bisect_commit = None
        if self.triage.get('auto_bisect'):
            log.info(f"Bisecting {crash['id']}...")
            bisector = Bisector(self.config, engine)
            bisect_commit = await bisector.bisect(crash)
            if bisect_commit:
                self._save_bisect(crash['id'], bisect_commit)
                crash['bisect_commit'] = bisect_commit

        # 3. パッチ案生成
        patch = None
        if self.triage.get('auto_patch'):
            log.info(f"Generating patch for {crash['id']}...")
            patcher = PatchGenerator(self.config)
            patch = await patcher.generate(crash, analysis)
            if patch:
                self._save_patch(crash['id'], patch)
                crash['patch'] = patch

        # 4. VRPレポート草稿生成
        report_md = self._generate_report(crash, analysis, bisect_commit, patch)
        self._save_report(crash['id'], report_md)

        # 5. Cloudflare KVにcrashをpush
        await self._push_to_kv('/report/crash', {
            'id':          crash['id'],
            'engine':      crash.get('engine', 'v8'),
            'crash_type':  analysis.get('crash_type', 'Unknown'),
            'component':   analysis.get('affected_component', 'Unknown'),
            'cvss':        analysis.get('cvss', 0.0),
            'exploitability': analysis.get('exploitability', 'unknown'),
            'reward_min':  analysis.get('estimated_reward_min', 0),
            'reward_max':  analysis.get('estimated_reward_max', 0),
            'vrp_eligible': analysis.get('vrp_eligible', False),
            'timestamp':   crash.get('timestamp', time.time()),
            'poc':         (crash.get('minimized_code') or crash.get('js_code', ''))[:500],
            'js_code':     crash.get('minimized_code') or crash.get('js_code', ''),
            'stderr':      crash.get('stderr', ''),
            'minimized':   bool(crash.get('minimized_code')),
            'vrp_report':  crash.get('vrp_report', ''),
        })

        # 6. 通知
        cvss = analysis.get('cvss', 0.0)
        threshold = self.notify['thresholds']['immediate']

        if cvss >= threshold:
            # 即時メール通知
            await self._send_immediate(crash, analysis, report_md)
        else:
            # 日次サマリーキューに追加
            self._daily_queue.append({
                'crash': crash,
                'analysis': analysis,
            })
            log.info(
                f"Queued for daily summary: {crash['id']} CVSS={cvss}"
            )

    def _generate_report(
        self, crash: dict, analysis: dict,
        bisect_commit: Optional[str], patch: Optional[str]
    ) -> str:
        """VRPレポートのMarkdown草稿を生成"""
        engine    = crash.get('engine', 'v8').upper()
        poc       = crash.get('minimized_code') or crash.get('js_code', '')
        now       = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        target    = analysis.get('target_program', 'Google Chrome VRP')

        report = f"""# {analysis.get('report_title', 'Security Bug Report')}

## Summary

{analysis.get('attack_scenario', 'Memory corruption bug in {engine}.')}

## Affected Version

- Engine: {engine}
- Reported: {now}
- Component: {analysis.get('affected_component', 'Unknown')}

## Severity

- Type: {analysis.get('crash_type', 'Unknown')}
- CVSS: {analysis.get('cvss', 0.0)}
- Exploitability: {analysis.get('exploitability', 'unknown')}
- Estimated Reward: ${analysis.get('estimated_reward_min', 0):,} ~ ${analysis.get('estimated_reward_max', 0):,}

## Reproduction Steps

1. Build d8/jsc with ASAN:
   ```bash
   # V8
   tools/dev/gm.py x64.asan
   # JSC
   Tools/Scripts/build-webkit --jsc-only --debug
   ```

2. Run the PoC:
   ```bash
   ./d8 --allow-natives-syntax poc.js
   ```

## Proof of Concept

```javascript
{poc[:3000]}
```

## Crash Output

```
{crash.get('stderr', '')[:2000]}
```
"""

        if bisect_commit:
            report += f"""
## Bisection

Introducing commit: `{bisect_commit[:8] if bisect_commit else 'TBD'}`

```bash
git bisect start
git bisect bad HEAD
git bisect good {bisect_commit[:8] if bisect_commit else 'KNOWN_GOOD'}
# ... bisect steps
```
"""

        if patch:
            report += f"""
## Suggested Fix

{patch}
"""

        report += f"""
## Impact

This vulnerability could allow an attacker to:
{analysis.get('attack_scenario', 'Cause memory corruption in the JavaScript engine.')}

---
*Generated by v8fuzz automated security research system*
*Target: {target}*
"""
        return report

    async def _send_immediate(
        self, crash: dict, analysis: dict, report_md: str
    ):
        """即時メール通知（CRITICAL: CVSS 8.0以上）"""
        cvss      = analysis.get('cvss', 0.0)
        est_min   = analysis.get('estimated_reward_min', 0)
        est_max   = analysis.get('estimated_reward_max', 0)
        poc       = (crash.get('minimized_code') or crash.get('js_code', ''))[:800]
        minimized = '&#10003; ' + 'Minimized' if crash.get('minimized_code') else '&#8987; Pending'
        bisect    = crash.get('bisect_commit', '')[:8] if crash.get('bisect_commit') else '&#8987; Pending'
        now       = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

        subject = (
            f"[CRITICAL] {crash['id']} · "
            f"{analysis.get('crash_type','?')} · "
            f"CVSS {cvss}"
        )

        html = f"""<!DOCTYPE html>
<html lang="ja">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:20px;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.08),0 8px 24px rgba(0,0,0,0.06);">

  <!-- ヘッダー -->
  <div style="background:#0f0f0f;padding:24px 32px;display:flex;align-items:center;justify-content:space-between;">
    <span style="color:#ffffff;font-size:14px;font-weight:700;letter-spacing:0.05em;">v8fuzz</span>
    <span style="background:#ef4444;color:#fff;font-size:10px;font-weight:700;padding:3px 12px;border-radius:100px;letter-spacing:0.08em;">CRITICAL</span>
  </div>

  <div style="padding:32px;">

    <!-- タイトル -->
    <div style="margin-bottom:24px;">
      <div style="font-size:11px;color:#6b7280;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:8px;">New Crash Detected · V8</div>
      <div style="font-size:22px;font-weight:700;color:#0f0f0f;line-height:1.3;">{analysis.get('crash_type','Unknown')}<br><span style="font-size:14px;font-weight:500;color:#6b7280;">{analysis.get('affected_component','Unknown Component')}</span></div>
    </div>

    <!-- メトリクス -->
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:24px;">
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:14px 16px;">
        <div style="font-size:10px;color:#ef4444;font-weight:600;letter-spacing:0.08em;margin-bottom:4px;">CVSS</div>
        <div style="font-size:26px;font-weight:800;color:#ef4444;line-height:1;">{cvss}</div>
      </div>
      <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:14px 16px;">
        <div style="font-size:10px;color:#6b7280;font-weight:600;letter-spacing:0.08em;margin-bottom:4px;">ID</div>
        <div style="font-size:14px;font-weight:700;color:#0f0f0f;line-height:1;padding-top:6px;">{crash['id']}</div>
      </div>
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:14px 16px;">
        <div style="font-size:10px;color:#16a34a;font-weight:600;letter-spacing:0.08em;margin-bottom:4px;">REWARD</div>
        <div style="font-size:12px;font-weight:700;color:#16a34a;line-height:1;padding-top:6px;">${est_min:,}–${est_max:,}</div>
      </div>
    </div>

    <!-- 詳細テーブル -->
    <div style="background:#f9fafb;border-radius:8px;padding:16px 20px;margin-bottom:24px;">
      <table style="width:100%;border-collapse:collapse;">
        <tr>
          <td style="padding:7px 0;font-size:12px;color:#6b7280;width:130px;">Exploitability</td>
          <td style="padding:7px 0;font-size:12px;"><span style="background:#fef2f2;color:#ef4444;font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;">{analysis.get('exploitability','?').upper()}</span></td>
        </tr>
        <tr style="border-top:1px solid #e5e7eb;">
          <td style="padding:7px 0;font-size:12px;color:#6b7280;">File</td>
          <td style="padding:7px 0;font-size:12px;color:#0f0f0f;font-weight:500;">{crash.get('id','?')}</td>
        </tr>
        <tr style="border-top:1px solid #e5e7eb;">
          <td style="padding:7px 0;font-size:12px;color:#6b7280;">Minimized</td>
          <td style="padding:7px 0;font-size:12px;color:#16a34a;font-weight:500;">{minimized}</td>
        </tr>
        <tr style="border-top:1px solid #e5e7eb;">
          <td style="padding:7px 0;font-size:12px;color:#6b7280;">Bisect</td>
          <td style="padding:7px 0;font-size:12px;color:#0f0f0f;font-family:monospace;">{bisect}</td>
        </tr>
      </table>
    </div>

    <!-- PoC -->
    <div style="margin-bottom:24px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;letter-spacing:0.08em;margin-bottom:8px;">MINIMIZED POC</div>
      <div style="background:#0f0f0f;border-radius:8px;padding:16px 20px;overflow-x:auto;">
        <pre style="margin:0;font-size:11px;color:#22c55e;font-family:'SF Mono','Cascadia Code',monospace;line-height:1.7;white-space:pre-wrap;">{poc}</pre>
      </div>
    </div>

    <!-- ボタン -->
    <a href="{self.config['api']['worker_url']}/crashes/{crash['id']}" style="display:block;background:#0f0f0f;color:#ffffff;text-align:center;padding:14px;border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;letter-spacing:0.03em;margin-bottom:10px;">View in Dashboard →</a>
    <a href="https://bughunters.google.com/report" style="display:block;background:#fef2f2;border:1px solid #fecaca;color:#ef4444;text-align:center;padding:12px;border-radius:8px;font-size:12px;font-weight:600;text-decoration:none;">Submit to Google VRP</a>
  </div>

  <!-- フッター -->
  <div style="padding:16px 32px;border-top:1px solid #f3f4f6;display:flex;justify-content:space-between;align-items:center;">
    <span style="font-size:11px;color:#9ca3af;">v8fuzz · automated security research</span>
    <span style="font-size:11px;color:#9ca3af;">{now}</span>
  </div>

</div>
</body></html>"""

        await self._send_email(subject, html)
        log.info(f"Immediate notification sent: {crash['id']}")

    async def send_daily_summary(self):
        """日次サマリーメールを送信"""
        stats = self._get_daily_stats()
        queue = self._daily_queue.copy()
        self._daily_queue.clear()

        now     = datetime.now(timezone.utc)
        datestr = now.strftime('%A, %B %d')

        subject = (
            f"[DAILY] {stats['v8_crashes']} crashes · "
            f"{stats['vrp_candidates']} VRP candidates · "
            f"V8"
        )

        # VRP候補リスト
        candidates_html = ""
        for item in queue[:10]:
            c = item['crash']
            a = item['analysis']
            cvss  = a.get('cvss', 0)
            color = '#ef4444' if cvss >= 8 else '#f59e0b' if cvss >= 6 else '#3b82f6'
            bg    = '#fef2f2' if cvss >= 8 else '#fffbeb' if cvss >= 6 else '#eff6ff'
            label = 'CRITICAL' if cvss >= 8 else 'HIGH' if cvss >= 6 else 'MEDIUM'
            candidates_html += f"""
        <div style="display:flex;align-items:center;padding:12px 16px;border-bottom:1px solid #f3f4f6;gap:12px;">
          <div style="width:4px;height:36px;background:{color};border-radius:2px;flex-shrink:0;"></div>
          <div style="flex:1;">
            <div style="font-size:12px;font-weight:600;color:#0f0f0f;">{c['id']} · {a.get('crash_type','?')}</div>
            <div style="font-size:11px;color:#6b7280;margin-top:2px;">{a.get('affected_component','Unknown')}</div>
          </div>
          <div style="text-align:right;margin-right:8px;">
            <div style="font-size:16px;font-weight:800;color:{color};">{cvss}</div>
            <div style="font-size:10px;color:#6b7280;">CVSS</div>
          </div>
          <span style="background:{bg};color:{color};font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;white-space:nowrap;">{label}</span>
        </div>"""

        no_candidates = "<div style='padding:16px;font-size:13px;color:#6b7280;text-align:center;'>本日のVRP候補はありません</div>"

        html = f"""<!DOCTYPE html>
<html lang="ja">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:20px;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.08),0 8px 24px rgba(0,0,0,0.06);">

  <!-- ヘッダー -->
  <div style="background:#0f0f0f;padding:24px 32px;">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <span style="color:#ffffff;font-size:14px;font-weight:700;letter-spacing:0.05em;">v8fuzz</span>
      <span style="background:#374151;color:#9ca3af;font-size:10px;font-weight:600;padding:3px 10px;border-radius:100px;letter-spacing:0.08em;">DAILY REPORT</span>
    </div>
    <div style="font-size:22px;font-weight:700;color:#ffffff;line-height:1.2;">{datestr}</div>
    <div style="font-size:12px;color:#6b7280;margin-top:4px;">V8 · Google VRP</div>
  </div>

  <div style="padding:32px;">

    <!-- KPI -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:28px;">
      <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px 20px;">
        <div style="font-size:10px;color:#6b7280;font-weight:600;letter-spacing:0.08em;margin-bottom:6px;">EXECUTIONS</div>
        <div style="font-size:20px;font-weight:800;color:#0f0f0f;">{stats['v8_execs']:,}</div>
        <div style="font-size:11px;color:#6b7280;margin-top:2px;">today</div>
      </div>
      <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px 20px;">
        <div style="font-size:10px;color:#6b7280;font-weight:600;letter-spacing:0.08em;margin-bottom:6px;">NEW SEEDS</div>
        <div style="font-size:20px;font-weight:800;color:#0f0f0f;">10,000</div>
        <div style="font-size:11px;color:#6b7280;margin-top:2px;">via Gemini</div>
      </div>
      <div style="border:1px solid {'#fecaca' if stats['v8_crashes'] > 0 else '#e5e7eb'};background:{'#fef2f2' if stats['v8_crashes'] > 0 else '#f9fafb'};border-radius:8px;padding:16px 20px;">
        <div style="font-size:10px;color:{'#ef4444' if stats['v8_crashes'] > 0 else '#6b7280'};font-weight:600;letter-spacing:0.08em;margin-bottom:6px;">CRASHES</div>
        <div style="font-size:20px;font-weight:800;color:{'#ef4444' if stats['v8_crashes'] > 0 else '#0f0f0f'};">{stats['v8_crashes']}</div>
        <div style="font-size:11px;color:{'#ef4444' if stats['vrp_candidates'] > 0 else '#6b7280'};margin-top:2px;">{stats['vrp_candidates']} VRP candidates</div>
      </div>
      <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px 20px;">
        <div style="font-size:10px;color:#6b7280;font-weight:600;letter-spacing:0.08em;margin-bottom:6px;">API SPEND</div>
        <div style="font-size:20px;font-weight:800;color:#0f0f0f;">${stats['api_spend']:.2f}</div>
        <div style="font-size:11px;color:#16a34a;margin-top:2px;">today</div>
      </div>
    </div>

    <!-- VRP候補 -->
    <div style="margin-bottom:24px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;letter-spacing:0.08em;margin-bottom:12px;">VRP CANDIDATES</div>
      <div style="border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
        {candidates_html if queue else no_candidates}
      </div>
    </div>

    <!-- CTA -->
    <a href="{self.config['api']['worker_url']}" style="display:block;background:#0f0f0f;color:#ffffff;text-align:center;padding:14px;border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;letter-spacing:0.03em;">Open Dashboard →</a>
  </div>

  <!-- フッター -->
  <div style="padding:16px 32px;border-top:1px solid #f3f4f6;display:flex;justify-content:space-between;align-items:center;">
    <span style="font-size:11px;color:#9ca3af;">v8fuzz · automated security research</span>
    <span style="font-size:11px;color:#9ca3af;">{now.strftime('%Y-%m-%d %H:%M UTC')}</span>
  </div>

</div>
</body></html>"""

        await self._send_email(subject, html)

        # KVにstatsをpush
        await self._push_to_kv('/report/stats', {
            'v8_crashes':     stats['v8_crashes'],
            'vrp_candidates': stats['vrp_candidates'],
            'v8_execs':       stats['v8_execs'],
            'api_spend':      stats['api_spend'],
            'updated_at':     time.time(),
        })

        log.info("Daily summary sent")

    async def _send_email(self, subject: str, html: str):
        """Gmail SMTPでメール送信"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_email_sync, subject, html)

    def _send_email_sync(self, subject: str, html: str):
        """Gmail SMTP同期送信"""
        gmail_user = self.notify['gmail_address']
        gmail_pass = self.notify['gmail_app_password']
        to_email   = self.notify['to_email']

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From']    = f"v8fuzz <{gmail_user}>"
            msg['To']      = to_email

            msg.attach(MIMEText(html, 'html'))

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(gmail_user, gmail_pass)
                server.sendmail(gmail_user, to_email, msg.as_string())

            log.info(f"Email sent: {subject[:50]}")
        except Exception as e:
            log.error(f"Gmail send error: {e}")

    def _get_daily_stats(self) -> dict:
        """当日の統計を取得"""
        cutoff = time.time() - 86400
        with sqlite3.connect(self.db_path) as db:
            v8 = db.execute("""
                SELECT COUNT(*) FROM crashes
                WHERE engine='v8' AND timestamp > ?
            """, (cutoff,)).fetchone()[0]

            jsc = db.execute("""
                SELECT COUNT(*) FROM crashes
                WHERE engine='jsc' AND timestamp > ?
            """, (cutoff,)).fetchone()[0]

            vrp = db.execute("""
                SELECT COUNT(*) FROM crashes
                WHERE vrp_eligible=1 AND timestamp > ?
            """, (cutoff,)).fetchone()[0]

            unique = db.execute("""
                SELECT COUNT(DISTINCT substr(stderr, 1, 200)) FROM crashes
                WHERE engine='v8' AND timestamp > ?
                AND stderr IS NOT NULL AND stderr != ''
            """, (cutoff,)).fetchone()[0]

        return {
            'v8_crashes':     v8,
            'unique_crashes': unique,
            'jsc_crashes':    jsc,
            'v8_execs':       0,   # runner.pyから取得予定
            'jsc_execs':      0,
            'total_execs':    0,
            'vrp_candidates': vrp,
            'api_spend':      0.0, # 実装予定
        }

    def _save_minimized(self, crash_id: str, code: str):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "UPDATE crashes SET minimized_code=? WHERE id=?",
                (code, crash_id)
            )

    def _save_bisect(self, crash_id: str, commit: str):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "UPDATE crashes SET bisect_commit=? WHERE id=?",
                (commit, crash_id)
            )

    def _save_patch(self, crash_id: str, patch: str):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "UPDATE crashes SET patch_code=? WHERE id=?",
                (patch, crash_id)
            )

    async def _push_to_kv(self, path: str, payload: dict):
        """Cloudflare Worker KVにデータをPOST"""
        api = self.config.get('api', {})
        worker_url = api.get('worker_url', '').rstrip('/')
        secret = api.get('secret', '')
        if not worker_url or not secret:
            return
        url = f"{worker_url}{path}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers={
                        'X-API-Secret': secret,
                        'Content-Type': 'application/json',
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status not in (200, 201):
                        log.warning(f"KV push failed: {path} status={resp.status}")
                    else:
                        log.debug(f"KV push ok: {path}")
        except Exception as e:
            log.warning(f"KV push error: {path} {e}")

    def _save_report(self, crash_id: str, report: str):
        """レポートをファイルとして保存"""
        from pathlib import Path
        report_dir = Path(self.config['infra']['log_dir']) / 'reports'
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / f"{crash_id}.md").write_text(report)
