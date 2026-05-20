"""
budget_guard.py: クレジット残高を監視して自動でDropletを削除する
- DO APIで残高を定期チェック
- 残高が閾値を下回ったらDropletを全削除
- Resendでメール通知
- systemdタイマーで1時間ごとに実行
"""
import json
import logging
import os
import sys
import urllib.request
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [budget_guard] %(levelname)s: %(message)s',
)
log = logging.getLogger('budget_guard')

# --- 設定 ---
DO_TOKEN        = os.environ.get('DO_TOKEN', '')
RESEND_API_KEY  = os.environ.get('RESEND_API_KEY', '')
ALERT_EMAIL     = os.environ.get('ALERT_EMAIL', '')
SAFE_THRESHOLD  = float(os.environ.get('SAFE_THRESHOLD', '20'))  # $20以下で削除


def do_get(path: str) -> dict:
    req = urllib.request.Request(
        f"https://api.digitalocean.com/v2{path}",
        headers={
            'Authorization': f'Bearer {DO_TOKEN}',
            'Content-Type': 'application/json',
        }
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def do_delete(path: str):
    req = urllib.request.Request(
        f"https://api.digitalocean.com/v2{path}",
        method='DELETE',
        headers={'Authorization': f'Bearer {DO_TOKEN}'},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def get_balance() -> float:
    """クレジット残高を取得"""
    data = do_get('/customers/my/balance')
    # account_balance = クレジット残高（正の値）
    balance = float(data.get('account_balance', '0'))
    month_to_date = float(data.get('month_to_date_usage', '0'))
    log.info(f"Balance: ${balance:.2f} | Month-to-date: ${month_to_date:.2f}")
    return balance


def get_droplets() -> list:
    """全Dropletを取得"""
    data = do_get('/droplets?per_page=100')
    return data.get('droplets', [])


def delete_all_droplets() -> int:
    """全Dropletを削除して削除数を返す"""
    droplets = get_droplets()
    deleted = 0
    for d in droplets:
        did  = d['id']
        name = d['name']
        try:
            status = do_delete(f'/droplets/{did}')
            log.info(f"Deleted Droplet: {name} (id={did}) → {status}")
            deleted += 1
        except Exception as e:
            log.error(f"Failed to delete {name}: {e}")
    return deleted


def send_alert(balance: float, deleted: int):
    """Resendでメール送信"""
    if not RESEND_API_KEY or not ALERT_EMAIL:
        log.warning("Resend not configured, skipping email")
        return

    subject = f"[v8fuzz] ⚠️ クレジット残高 ${balance:.2f} → Droplet {deleted}台を自動削除"
    html = f"""
<div style="font-family: monospace; max-width: 600px;">
  <h2 style="color: #d29922;">⚠️ 自動削除実行</h2>
  <p>クレジット残高が閾値 <b>${SAFE_THRESHOLD:.0f}</b> を下回ったため、
  全Dropletを自動削除しました。</p>
  <table style="border-collapse:collapse;">
    <tr><td style="padding:6px;color:#666;">残高</td>
        <td style="padding:6px;color:#d73a49;"><b>${balance:.2f}</b></td></tr>
    <tr><td style="padding:6px;color:#666;">削除台数</td>
        <td style="padding:6px;"><b>{deleted}台</b></td></tr>
  </table>
  <p>カードへの課金は発生していません。<br>
  再開する場合は新しいDropletを作成してください。</p>
</div>
"""

    payload = json.dumps({
        "from":    "v8fuzz@yourdomain.com",
        "to":      [ALERT_EMAIL],
        "subject": subject,
        "html":    html,
    }).encode()

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            'Authorization': f'Bearer {RESEND_API_KEY}',
            'Content-Type': 'application/json',
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            log.info(f"Alert email sent: {resp.status}")
    except Exception as e:
        log.error(f"Email failed: {e}")


def main():
    if not DO_TOKEN:
        log.error("DO_TOKEN not set")
        sys.exit(1)

    try:
        balance = get_balance()
    except Exception as e:
        log.error(f"Failed to get balance: {e}")
        sys.exit(1)

    if balance <= SAFE_THRESHOLD:
        log.warning(
            f"Balance ${balance:.2f} <= threshold ${SAFE_THRESHOLD:.2f} "
            f"→ deleting all Droplets"
        )
        deleted = delete_all_droplets()
        send_alert(balance, deleted)
        log.info(f"Done. Deleted {deleted} Droplets.")
    else:
        log.info(
            f"Balance OK: ${balance:.2f} "
            f"(threshold: ${SAFE_THRESHOLD:.2f})"
        )


if __name__ == '__main__':
    main()
