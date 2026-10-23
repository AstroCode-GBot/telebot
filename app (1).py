"""ModifyXHUB Telegram bot webhook + REST API.

Compatible with the existing ModifyXHUB MySQL schema:
  telegram_contacts(telegram_id, chat_id, username, username_key,
                    first_name, last_name, last_seen_at, created_at)
  login_codes(telegram_id, username_key, code_hash, expires_at,
              attempts, last_sent_at, created_at)

Run locally / on WSGI hosts: gunicorn app:app
Vercel detects the Flask app from app.py. All durable state stays in MySQL.
"""
from __future__ import annotations

import hmac
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import bcrypt
import pymysql
import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from pymysql.cursors import DictCursor

load_dotenv()

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("modifyxhub-bot")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

APP_NAME = "ModifyXHUB Telegram Bot API"
APP_VERSION = "1.0.0"
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "").strip()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", os.getenv("SITE_URL", "")).strip().rstrip("/")
WEBHOOK_PATH = os.getenv("WEBHOOK_PATH", "/telegram_webhook").strip()
if not WEBHOOK_PATH.startswith("/"):
    WEBHOOK_PATH = "/" + WEBHOOK_PATH
if WEBHOOK_PATH not in ("/telegram_webhook", "/telegram_webhook.php"):
    # Keep the public webhook path predictable and avoid arbitrary path config.
    WEBHOOK_PATH = "/telegram_webhook"

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}" if BOT_TOKEN else ""
UID_RE = re.compile(r"^[1-9][0-9]{0,18}$")
SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


def json_error(message: str, status: int, **extra: Any):
    body = {"ok": False, "error": message}
    body.update(extra)
    response = jsonify(body)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


def db_configured() -> bool:
    required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASS")
    return all(os.getenv(key, "").strip() for key in required)


def get_db():
    if not db_configured():
        raise RuntimeError("Database settings are not configured.")

    kwargs: dict[str, Any] = {
        "host": os.environ["DB_HOST"].strip(),
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.environ["DB_USER"].strip(),
        "password": os.environ["DB_PASS"],
        "database": os.environ["DB_NAME"].strip(),
        "charset": "utf8mb4",
        "cursorclass": DictCursor,
        "connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "8")),
        "read_timeout": int(os.getenv("DB_READ_TIMEOUT", "12")),
        "write_timeout": int(os.getenv("DB_WRITE_TIMEOUT", "12")),
        "autocommit": False,
    }
    ssl_mode = os.getenv("DB_SSL", "false").lower() in {"1", "true", "yes", "on"}
    if ssl_mode:
        ca_file = os.getenv("DB_SSL_CA", "").strip()
        ssl_opts: dict[str, Any] = {"check_hostname": True}
        if ca_file:
            ssl_opts["ca"] = ca_file
        kwargs["ssl"] = ssl_opts
    connection = pymysql.connect(**kwargs)
    with connection.cursor() as cursor:
        cursor.execute("SET time_zone = '+00:00'")
    return connection


def secrets_configured() -> bool:
    return bool(BOT_TOKEN and WEBHOOK_SECRET and SECRET_RE.fullmatch(WEBHOOK_SECRET))


def api_key_valid() -> bool:
    if not INTERNAL_API_KEY:
        return False
    incoming = request.headers.get("X-Internal-API-Key", "")
    return bool(incoming) and hmac.compare_digest(incoming, INTERNAL_API_KEY)


def require_internal_key():
    if not INTERNAL_API_KEY:
        return json_error("Internal API is not configured.", 503)
    if not api_key_valid():
        return json_error("Unauthorized.", 401)
    return None


def telegram_call(method: str, payload: dict[str, Any], timeout: int = 15) -> dict[str, Any]:
    if not BOT_TOKEN:
        raise RuntimeError("Telegram bot token is not configured.")
    try:
        response = requests.post(
            f"{TELEGRAM_API}/{method}",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        logger.warning("Telegram API request failed for %s: %s", method, type(exc).__name__)
        raise RuntimeError("Telegram API request failed. Check bot token and outbound HTTPS.") from exc
    except ValueError as exc:
        raise RuntimeError("Telegram returned an invalid response.") from exc
    if not isinstance(data, dict) or not data.get("ok"):
        description = data.get("description", "Telegram returned an error") if isinstance(data, dict) else "Invalid Telegram response"
        logger.warning("Telegram API rejected %s: %s", method, description)
        raise RuntimeError(str(description))
    return data


def send_message(chat_id: int | str, text: str) -> None:
    telegram_call("sendMessage", {
        "chat_id": str(chat_id),
        "text": text,
        "disable_web_page_preview": True,
    })


def store_private_contact(message: dict[str, Any]) -> tuple[int, int, str | None]:
    sender = message.get("from") or {}
    chat = message.get("chat") or {}
    try:
        telegram_id = int(sender.get("id"))
        chat_id = int(chat.get("id"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Missing Telegram user or chat ID") from exc

    # Login OTPs must only go to the user's private chat, never a group chat.
    if str(chat.get("type", "")) != "private" or chat_id != telegram_id:
        raise ValueError("Start the bot in a private chat to register your Telegram ID.")

    raw_username = sender.get("username")
    username = str(raw_username)[:32] if raw_username else None
    username_key = username.lower() if username else None
    first_name = str(sender.get("first_name", ""))[:128] or None
    last_name = str(sender.get("last_name", ""))[:128] or None

    connection = get_db()
    try:
        with connection.cursor() as cursor:
            if username_key:
                # Telegram usernames can change hands. Keep a unique username mapping,
                # but never use it as the authentication identity.
                cursor.execute(
                    "DELETE FROM telegram_contacts WHERE username_key=%s AND telegram_id<>%s",
                    (username_key, telegram_id),
                )
            cursor.execute(
                """INSERT INTO telegram_contacts
                   (telegram_id, chat_id, username, username_key, first_name, last_name, last_seen_at)
                   VALUES (%s, %s, %s, %s, %s, %s, UTC_TIMESTAMP())
                   ON DUPLICATE KEY UPDATE
                     chat_id=VALUES(chat_id), username=VALUES(username),
                     username_key=VALUES(username_key), first_name=VALUES(first_name),
                     last_name=VALUES(last_name), last_seen_at=UTC_TIMESTAMP()""",
                (telegram_id, chat_id, username, username_key, first_name, last_name),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return telegram_id, chat_id, username


def handle_telegram_update(update: dict[str, Any]) -> None:
    message = update.get("message")
    if not isinstance(message, dict):
        return
    chat = message.get("chat") or {}
    sender = message.get("from") or {}
    text = str(message.get("text") or "").strip()
    if not text or not sender.get("id") or not chat.get("id"):
        return

    # Ignore group/supergroup/channel updates to ensure login IDs are only linked to DMs.
    if str(chat.get("type", "")) != "private":
        return

    telegram_id, chat_id, _username = store_private_contact(message)
    command = text.split(maxsplit=1)[0].split("@", 1)[0].lower()
    if command == "/start":
        reply = (
            "Welcome to ModifyXHUB! ✅\n\n"
            f"YOUR USERID IS : {telegram_id}\n\n"
            "Copy this numeric USERID and paste it into the website login page. "
            "Then request a one-time verification code; it will be sent to this Telegram chat.\n\n"
            "A Telegram username is not required. Never share your verification code."
        )
    elif command in ("/help", "/id", "/userid"):
        reply = (
            "ModifyXHUB login help\n\n"
            f"YOUR USERID IS : {telegram_id}\n\n"
            "1. Copy the numeric USERID above.\n"
            "2. Enter it on the website login page.\n"
            "3. Request a one-time code and enter it on the website.\n\n"
            "Codes expire after 5 minutes. A Telegram username is not required."
        )
    else:
        reply = (
            "ModifyXHUB website login bot.\n\n"
            f"YOUR USERID IS : {telegram_id}\n\n"
            "Send /start to view your ID and connect this Telegram chat to your website account."
        )
    send_message(chat_id, reply)


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/")
def root():
    return jsonify({
        "ok": True,
        "service": APP_NAME,
        "version": APP_VERSION,
        "health": "/health",
        "webhook": WEBHOOK_PATH,
        "docs": "See README.md for API usage and deployment.",
    })


@app.get("/health")
@app.get("/api/health")
def health():
    configured = {
        "telegram_token": bool(BOT_TOKEN),
        "telegram_webhook_secret": bool(WEBHOOK_SECRET and SECRET_RE.fullmatch(WEBHOOK_SECRET)),
        "internal_api_key": bool(INTERNAL_API_KEY),
        "database_env": db_configured(),
    }
    database_status = "not_configured"
    if configured["database_env"]:
        connection = None
        try:
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 AS ping")
                cursor.fetchone()
            database_status = "ok"
        except Exception as exc:
            database_status = "unavailable"
            logger.warning("Health check database failed: %s", type(exc).__name__)
        finally:
            if connection:
                connection.close()
    ready = all((configured["telegram_token"], configured["telegram_webhook_secret"], configured["database_env"])) and database_status == "ok"
    return jsonify({
        "ok": ready,
        "service": APP_NAME,
        "version": APP_VERSION,
        "database": database_status,
        "configured": configured,
        "note": "Secrets are intentionally not returned by this endpoint.",
    }), (200 if ready else 503)


@app.route("/telegram_webhook", methods=["POST"])
@app.route("/telegram_webhook.php", methods=["POST"])
def telegram_webhook():
    if not secrets_configured():
        return "Webhook is not configured", 503, {"Content-Type": "text/plain; charset=utf-8"}
    incoming = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not incoming or not hmac.compare_digest(incoming, WEBHOOK_SECRET):
        return "Forbidden", 403, {"Content-Type": "text/plain; charset=utf-8"}
    update = request.get_json(silent=True)
    if not isinstance(update, dict):
        return "Invalid update", 400, {"Content-Type": "text/plain; charset=utf-8"}
    try:
        handle_telegram_update(update)
    except ValueError as exc:
        # Ignore non-private or malformed messages safely; Telegram receives 200.
        logger.info("Telegram update ignored: %s", str(exc))
    except Exception as exc:
        logger.exception("Telegram webhook processing failed: %s", type(exc).__name__)
        return "Temporary error", 500, {"Content-Type": "text/plain; charset=utf-8"}
    return "OK", 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.post("/api/admin/set-webhook")
def set_webhook():
    key_error = require_internal_key()
    if key_error:
        return key_error
    if not secrets_configured():
        return json_error("Set TELEGRAM_BOT_TOKEN and TELEGRAM_WEBHOOK_SECRET first.", 503)
    if not PUBLIC_BASE_URL.startswith("https://"):
        return json_error("Set PUBLIC_BASE_URL to your public HTTPS deployment URL first.", 422)
    webhook_url = PUBLIC_BASE_URL + WEBHOOK_PATH
    try:
        result = telegram_call("setWebhook", {
            "url": webhook_url,
            "secret_token": WEBHOOK_SECRET,
            "allowed_updates": ["message"],
            "drop_pending_updates": False,
            "max_connections": 20,
        })
    except Exception as exc:
        logger.warning("setWebhook failed: %s", type(exc).__name__)
        return json_error("Telegram rejected setWebhook. Check bot token, URL, secret and HTTPS.", 502)
    return jsonify({"ok": True, "webhook_url": webhook_url, "telegram": result.get("description", "Webhook configured")})


@app.get("/api/admin/webhook-info")
def webhook_info():
    key_error = require_internal_key()
    if key_error:
        return key_error
    try:
        data = telegram_call("getWebhookInfo", {})
    except Exception as exc:
        logger.warning("getWebhookInfo failed: %s", type(exc).__name__)
        return json_error("Could not retrieve Telegram webhook info.", 502)
    result = data.get("result", {})
    # Only return diagnostic fields; never include the bot token.
    return jsonify({
        "ok": True,
        "url": result.get("url", ""),
        "has_custom_certificate": result.get("has_custom_certificate", False),
        "pending_update_count": result.get("pending_update_count", 0),
        "last_error_date": result.get("last_error_date"),
        "last_error_message": result.get("last_error_message"),
        "max_connections": result.get("max_connections"),
        "allowed_updates": result.get("allowed_updates"),
    })


@app.get("/api/admin/contact/<telegram_id>")
def contact_status(telegram_id: str):
    key_error = require_internal_key()
    if key_error:
        return key_error
    if not UID_RE.fullmatch(telegram_id):
        return json_error("telegram_id must be a positive numeric Telegram user ID.", 422)
    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT telegram_id, username, first_name, last_seen_at FROM telegram_contacts WHERE telegram_id=%s LIMIT 1",
                (int(telegram_id),),
            )
            row = cursor.fetchone()
        if not row:
            return jsonify({"ok": True, "started": False, "telegram_id": int(telegram_id)})
        seen = row.get("last_seen_at")
        return jsonify({
            "ok": True,
            "started": True,
            "telegram_id": int(row["telegram_id"]),
            "username": row.get("username"),
            "first_name": row.get("first_name"),
            "last_seen_at": seen.isoformat() if seen else None,
        })
    except Exception as exc:
        logger.exception("Contact lookup failed: %s", type(exc).__name__)
        return json_error("Database lookup failed.", 503)
    finally:
        if connection:
            connection.close()


@app.post("/api/auth/request-code")
def request_login_code():
    """Server-to-server OTP sender compatible with the existing PHP login.php.

    Requires X-Internal-API-Key. It saves a bcrypt hash with PHP-compatible $2y$
    prefix into login_codes and username_key='uid:<telegram_id>', so the current
    PHP login.php verify_code action can verify this challenge.
    """
    key_error = require_internal_key()
    if key_error:
        return key_error
    body = request.get_json(silent=True) or {}
    raw_uid = str(body.get("telegram_id", "")).strip()
    if not UID_RE.fullmatch(raw_uid):
        return json_error("Enter the numeric Telegram USERID from /start.", 422)
    telegram_id = int(raw_uid)
    identity_key = f"uid:{telegram_id}"

    connection = None
    code_hash = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Lock the contact row so concurrent requests for the same ID serialize.
            cursor.execute("SELECT chat_id FROM telegram_contacts WHERE telegram_id=%s FOR UPDATE", (telegram_id,))
            contact = cursor.fetchone()
            if not contact:
                connection.rollback()
                return json_error("User has not started the bot yet. Open it and tap Start first.", 404, needs_start=True)

            cursor.execute("SELECT last_sent_at FROM login_codes WHERE telegram_id=%s", (telegram_id,))
            prior = cursor.fetchone()
            if prior and prior.get("last_sent_at"):
                last_sent = prior["last_sent_at"]
                if last_sent.tzinfo is not None:
                    last_sent = last_sent.astimezone(timezone.utc).replace(tzinfo=None)
                elapsed = (datetime.utcnow() - last_sent).total_seconds()
                if elapsed < 60:
                    connection.rollback()
                    wait_seconds = max(1, int(60 - elapsed))
                    return json_error("Wait before requesting another verification code.", 429, retry_after_seconds=wait_seconds)

            code = f"{secrets.randbelow(900000) + 100000:06d}"
            # PHP password_verify() accepts bcrypt's $2y$ variant. Re-labeling the
            # bcrypt prefix is safe because $2y$ uses the same bcrypt computation.
            code_hash = bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
            if code_hash.startswith("$2b$"):
                code_hash = "$2y$" + code_hash[4:]
            cursor.execute(
                """INSERT INTO login_codes
                   (telegram_id, username_key, code_hash, expires_at, attempts, last_sent_at)
                   VALUES (%s, %s, %s, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 5 MINUTE), 0, UTC_TIMESTAMP())
                   ON DUPLICATE KEY UPDATE username_key=VALUES(username_key), code_hash=VALUES(code_hash),
                     expires_at=VALUES(expires_at), attempts=0, last_sent_at=UTC_TIMESTAMP()""",
                (telegram_id, identity_key, code_hash),
            )
        connection.commit()
        try:
            send_message(
                int(contact["chat_id"]),
                "ModifyXHUB login verification\n\n"
                f"Your one-time code is: {code}\n\n"
                "It expires in 5 minutes. Never share this code with anyone. "
                "If you did not request it, ignore this message.",
            )
        except Exception:
            # Do not leave a usable code behind when Telegram could not deliver it.
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM login_codes WHERE telegram_id=%s AND code_hash=%s",
                    (telegram_id, code_hash),
                )
            connection.commit()
            return json_error("Telegram could not send the code. Open the bot and tap Start, then retry.", 502)
        return jsonify({"ok": True, "message": "Verification code sent to your Telegram chat.", "expires_in_seconds": 300})
    except Exception as exc:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        logger.exception("OTP request failed: %s", type(exc).__name__)
        return json_error("The login service is not ready. Check database and bot settings.", 503)
    finally:
        if connection:
            connection.close()


@app.errorhandler(413)
def request_too_large(_exc):
    return json_error("Request body is too large.", 413)


@app.errorhandler(404)
def not_found(_exc):
    return json_error("Endpoint not found.", 404)


@app.errorhandler(405)
def method_not_allowed(_exc):
    return json_error("Method not allowed.", 405)


if __name__ == "__main__":
    # Development only. In production, use Vercel or gunicorn.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
