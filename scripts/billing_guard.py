"""
BillingGuard: DOのクレジット残高を監視して自動停止
絶対に$200を超えて課金されないようにする
"""
import json
import logging
import os
import sys
import time
import urllib.request
import urllib.error

log = logging.getLogger('billing_guard')

DO_API = "https://api.digitalocean.com/v2"

def get_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

def api_get(token: str, path: str) -> dict:
    req = urllib.request.Request(
        f"{DO_API}{path}",
        headers=get_headers(token)
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())

def get_balance(token: str) -> dict:
    """クレジット残高を取得"""
    data = api_get(token, "/customers/my/balance")
    return {
        "credits":    float(data.get("account_balance", 0)),
        "month_usage": float(data.get("month_to_date_usage", 0)),
        "month_charge": float(data.get("month_to_date_balance", 0)),
    }

def get_droplets(token: str) -> list:
    """全Dropletのリストを取得"""
    data = api_get(token, "/droplets")
    return data.get("droplets", [])

def delete_droplet(token: str, droplet_id: int, name: str):
    """Dropletを削除（課金即停止）"""
    req = urllib.request.Request(
        f"{DO_API}/droplets/{droplet_id}",
        headers=get_headers(token),
        method="DELETE"
    )
    try:
        urllib.request.urlopen(req, timeout=30)
        log.warning(f"Droplet DELETED: {name} (id={droplet_id})")
    except urllib.error.HTTPError as e:
        log.error(f"Delete failed: {e}")

def send_alert_email(subject: str, body: str, config: dict):
    """Resendでメール送信"""
    payload = json.dumps({
        "from":    config.get("from_email", "v8fuzz@yourdomain.com"),
        "to":      [config.get("to_email", "you@gmail.com")],
        "subject": subject,
        "html":    f"<pre>{body}</pre>",
    }).encode()

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {config['resend_api_key']}",
            "Content-Type": "application/json",
        }
    )
    try:
        urllib.request.urlopen(req, timeout=30)
        log.info(f"Alert email sent: {subject}")
    except Exception as e:
        log.error(f"Email failed: {e}")

def check_and_guard(do_token: str, config: dict):
    """
    残高チェック → 必要に応じて自動停止
    """
    # 閾値設定
    WARN_THRESHOLD   = 30.0  # $30以下でメール警告
    STOP_THRESHOLD   = 10.0  # $10以下でDroplet削除

    try:
        balance = get_balance(do_token)
        credits  = balance["credits"]
        usage    = balance["month_usage"]

        log.info(
            f"Balance: credits=${credits:.2f} "
            f"usage_this_month=${usage:.2f}"
        )

        # クレジット残高がマイナス = 既に課金されている
        if credits < 0:
            msg = f"""
⚠️ 警告: DOクレジットが枯渇・課金が発生しています

クレジット残高: ${credits:.2f}
今月の使用額:   ${usage:.2f}

至急 https://cloud.digitalocean.com/billing を確認してください
"""
            send_alert_email(
                "[CRITICAL] DO課金発生！即確認を",
                msg, config
            )
            # 全Dropletを削除
            droplets = get_droplets(do_token)
            for d in droplets:
                delete_droplet(do_token, d["id"], d["name"])
            return

        # 警告閾値
        if credits <= WARN_THRESHOLD:
            msg = f"""
⚠️ DOクレジット残高が少なくなっています

クレジット残高: ${credits:.2f}
今月の使用額:   ${usage:.2f}

残高が${STOP_THRESHOLD}以下になると自動停止します
https://cloud.digitalocean.com/billing
"""
            send_alert_email(
                f"[WARNING] DOクレジット残り${credits:.2f}",
                msg, config
            )
            log.warning(f"Low balance warning: ${credits:.2f}")

        # 停止閾値 → Droplet削除
        if credits <= STOP_THRESHOLD:
            droplets = get_droplets(do_token)
            if not droplets:
                log.info("No droplets to delete")
                return

            names = [d["name"] for d in droplets]
            msg = f"""
🛑 DOクレジット残高 ${credits:.2f} → Dropletを自動削除しました

削除したDroplet: {", ".join(names)}
今月の使用額: ${usage:.2f}

これ以上の課金は発生しません。
新しいクレジットを追加するまでfuzzingは停止します。
"""
            send_alert_email(
                f"[STOP] Droplet自動削除 残高${credits:.2f}",
                msg, config
            )

            for d in droplets:
                delete_droplet(do_token, d["id"], d["name"])
                time.sleep(1)

            log.warning(f"All droplets deleted. Balance was ${credits:.2f}")

    except Exception as e:
        log.error(f"BillingGuard error: {e}")


def main():
    """
    使い方:
      python billing_guard.py <DO_TOKEN> <CONFIG_JSON>

    Crontabに登録（1時間ごと）:
      0 * * * * /opt/v8fuzz/venv/bin/python /opt/v8fuzz/app/scripts/billing_guard.py
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [billing_guard] %(levelname)s: %(message)s'
    )

    import yaml
    config_path = os.path.join(
        os.path.dirname(__file__), '..', 'config', 'config.yaml'
    )
    with open(config_path) as f:
        config = yaml.safe_load(f)

    do_token = os.environ.get("DO_API_TOKEN", "")
    if not do_token:
        log.error("DO_API_TOKEN environment variable not set")
        sys.exit(1)

    check_and_guard(do_token, config['notification'])


if __name__ == '__main__':
    main()
