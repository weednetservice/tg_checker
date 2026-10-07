import asyncio
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import questionary
import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

BASE_DIR = Path(__file__).resolve().parent
SESSIONS_DIR = BASE_DIR / "sessions"
OUTPUT_DIR = BASE_DIR / "output"
VALID_DIR = OUTPUT_DIR / "valid"
INVALID_DIR = OUTPUT_DIR / "invalid"
TWOFACTORAUTH_DIR = OUTPUT_DIR / "2fa"
RETRY_DIR = OUTPUT_DIR / "retry"
REPORT_PATH = OUTPUT_DIR / "report.txt"
CONFIG_PATH = BASE_DIR / "config.json"

DEFAULT_API_ID = 6
DEFAULT_API_HASH = "eb06d4abfb49dc3eeb1aeb98ae0f581e"
DEFAULT_THREADS = 15
MAX_THREADS = 50
MAX_RETRIES = 2
SPAMBOT_TIMEOUT = 10.0

console = Console()


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_private(path, content):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_config():
    if not CONFIG_PATH.exists():
        return {}
    try:
        if CONFIG_PATH.is_symlink():
            raise OSError("config.json must not be a symbolic link")
        os.chmod(CONFIG_PATH, 0o600)
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if isinstance(config, dict):
            return config
    except (OSError, ValueError):
        pass
    console.print("[yellow]Invalid config.json; using defaults.[/yellow]")
    return {}


def save_config(config):
    write_private(CONFIG_PATH, json.dumps(config, indent=2, ensure_ascii=False) + "\n")


def ensure_dirs():
    for directory in (SESSIONS_DIR, OUTPUT_DIR, VALID_DIR, INVALID_DIR, TWOFACTORAUTH_DIR, RETRY_DIR):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)


def session_files():
    return [
        entry.stem
        for entry in sorted(SESSIONS_DIR.iterdir())
        if entry.suffix == ".session" and entry.is_file() and not entry.is_symlink()
    ]


def session_authorized(name):
    path = SESSIONS_DIR / f"{name}.session"
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=2)) as database:
        row = database.execute(
            "SELECT auth_key, user_id, test_mode, is_bot FROM sessions LIMIT 1"
        ).fetchone()
    return bool(row and row[0] and row[1] and row[2] is not None and row[3] is not None)


def session_sidecars(name):
    path = SESSIONS_DIR / f"{name}.session"
    return any(Path(f"{path}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal"))


def api_credentials():
    raw_id = os.getenv("TG_API_ID") or str(DEFAULT_API_ID)
    api_hash = os.getenv("TG_API_HASH") or DEFAULT_API_HASH
    try:
        api_id = int(raw_id)
    except ValueError as error:
        raise ValueError("TG_API_ID must be a positive integer") from error
    if api_id <= 0 or not re.fullmatch(r"[0-9a-fA-F]{32}", api_hash):
        raise ValueError("TG_API_ID or TG_API_HASH is invalid")
    return api_id, api_hash


def destination_for(status):
    if status == "valid":
        return VALID_DIR
    if status == "2fa":
        return TWOFACTORAUTH_DIR
    if status in ("invalid", "banned", "deactivated", "login_required"):
        return INVALID_DIR
    return RETRY_DIR


def move_session(name, status):
    destination = destination_for(status)
    source_session = SESSIONS_DIR / f"{name}.session"
    source_json = SESSIONS_DIR / f"{name}.json"
    if source_json.is_symlink():
        raise ValueError("Session metadata must not be a symbolic link")
    if session_sidecars(name):
        raise OSError("Session has active SQLite sidecar files")
    directories = (VALID_DIR, INVALID_DIR, TWOFACTORAUTH_DIR, RETRY_DIR)
    stored_name = name
    while any(
        (directory / f"{stored_name}.session").exists() or (directory / f"{stored_name}.json").exists()
        for directory in directories
    ):
        stored_name = f"{name}_{uuid4().hex[:8]}"
    target_session = destination / f"{stored_name}.session"
    target_json = destination / f"{stored_name}.json"
    with tempfile.TemporaryDirectory(prefix=".session.", dir=destination) as temporary:
        staged_session = Path(temporary) / target_session.name
        staged_json = Path(temporary) / target_json.name
        shutil.copy2(source_session, staged_session)
        os.chmod(staged_session, 0o600)
        with staged_session.open("rb") as staged_file:
            os.fsync(staged_file.fileno())
        has_json = source_json.is_file()
        if has_json:
            shutil.copy2(source_json, staged_json)
            os.chmod(staged_json, 0o600)
            with staged_json.open("rb") as staged_file:
                os.fsync(staged_file.fileno())
        created_session = False
        created_json = False
        try:
            os.link(staged_session, target_session)
            created_session = True
            if has_json:
                os.link(staged_json, target_json)
                created_json = True
            sync_directory(destination)
        except OSError:
            if created_json and target_json.exists() and target_json.samefile(staged_json):
                target_json.unlink()
            if created_session and target_session.exists() and target_session.samefile(staged_session):
                target_session.unlink()
            raise
    if session_sidecars(name):
        target_session.unlink(missing_ok=True)
        target_json.unlink(missing_ok=True)
        sync_directory(destination)
        raise OSError("Session became active while being copied")
    try:
        if has_json:
            source_json.unlink()
        source_session.unlink()
        sync_directory(SESSIONS_DIR)
    except OSError as error:
        return stored_name, f"Source cleanup failed: {error_text(error)}"
    return stored_name, ""


def extract_ban_date(message):
    match = re.search(r"\b(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})\b", message)
    return f"{match.group(1)} {match.group(2)} {match.group(3)}" if match else None


async def check_spamblock(app, is_bot):
    if is_bot:
        return "N/A"
    try:
        sent = await app.send_message("SpamBot", "/start")
        deadline = asyncio.get_running_loop().time() + SPAMBOT_TIMEOUT
        while True:
            async for message in app.get_chat_history("SpamBot", limit=5):
                if message.id <= sent.id or message.outgoing:
                    continue
                response = (message.text or message.caption or "").strip()
                if "good news" in response.casefold():
                    return "Clean"
                date = extract_ban_date(response)
                return f"Restricted until {date}" if date else "Unknown"
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return "No reply"
            await asyncio.sleep(min(1.0, remaining))
    except Exception as error:
        return f"Unavailable ({type(error).__name__})"


async def grab_info(app):
    me = await app.get_me()
    return {
        "id": str(me.id),
        "username": me.username or "-",
        "first": me.first_name or "-",
        "last": me.last_name or "-",
        "phone": me.phone or "-",
        "premium": "Yes" if getattr(me, "is_premium", False) else "No",
        "bot": "Yes" if me.is_bot else "No",
    }


def empty_result():
    return {"id": "-", "username": "-", "first": "-", "last": "-", "phone": "-", "premium": "-", "bot": "-"}


def error_text(error):
    message = " ".join(str(error).split())
    return f"{type(error).__name__}: {message}"[:160] if message else type(error).__name__


async def close_client(app):
    if app.is_initialized:
        await asyncio.wait_for(app.stop(), timeout=20)
    elif app.is_connected:
        await asyncio.wait_for(app.disconnect(), timeout=20)


async def inspect_session(name, api_id, api_hash):
    from pyrogram import Client, raw
    from pyrogram.errors import (
        AuthBytesInvalid,
        AuthKeyDuplicated,
        AuthKeyInvalid,
        AuthKeyUnregistered,
        FloodWait,
        SessionExpired,
        SessionPasswordNeeded,
        SessionRevoked,
        UserDeactivated,
        UserDeactivatedBan,
    )

    info = empty_result()
    spam = "-"
    if session_sidecars(name):
        return {
            "name": name,
            "status": "error",
            **info,
            "spam": spam,
            "reason": "Session has active SQLite sidecar files",
            "keep_source": True,
        }
    try:
        if not await asyncio.to_thread(session_authorized, name):
            return {
                "name": name,
                "status": "login_required",
                **info,
                "spam": spam,
                "reason": "Session is not authorized",
            }
    except sqlite3.OperationalError as error:
        return {
            "name": name,
            "status": "error",
            **info,
            "spam": spam,
            "reason": error_text(error),
            "keep_source": True,
        }
    except sqlite3.DatabaseError as error:
        return {"name": name, "status": "invalid", **info, "spam": spam, "reason": error_text(error)}
    except OSError as error:
        return {
            "name": name,
            "status": "error",
            **info,
            "spam": spam,
            "reason": error_text(error),
            "keep_source": True,
        }

    for attempt in range(MAX_RETRIES + 1):
        app = Client(name=name, api_id=api_id, api_hash=api_hash, workdir=str(SESSIONS_DIR), no_updates=True)
        status = "error"
        reason = ""
        try:
            await asyncio.wait_for(app.start(), timeout=45)
            info = await asyncio.wait_for(grab_info(app), timeout=20)
            is_bot = info["bot"] == "Yes"
            password = None if is_bot else await asyncio.wait_for(
                app.invoke(raw.functions.account.GetPassword()), timeout=20
            )
            has_2fa = bool(password and password.has_password)
            try:
                spam = await asyncio.wait_for(check_spamblock(app, is_bot), timeout=SPAMBOT_TIMEOUT + 5)
            except TimeoutError:
                spam = "Unavailable (TimeoutError)"
            status = "2fa" if has_2fa else "valid"
        except UserDeactivatedBan as error:
            status, reason = "banned", error_text(error)
        except UserDeactivated as error:
            status, reason = "deactivated", error_text(error)
        except (
            AuthBytesInvalid,
            AuthKeyDuplicated,
            AuthKeyInvalid,
            AuthKeyUnregistered,
            SessionExpired,
            SessionRevoked,
        ) as error:
            status, reason = "invalid", error_text(error)
        except SessionPasswordNeeded as error:
            status, reason = "login_required", error_text(error)
        except FloodWait as error:
            status, reason = "flood", f"Retry after {error.value}s"
        except Exception as error:
            status, reason = "error", error_text(error)
        finally:
            try:
                await close_client(app)
            except Exception as error:
                status, reason = "error", f"Cleanup failed: {error_text(error)}"
        if status != "error" or attempt == MAX_RETRIES:
            return {"name": name, "status": status, **info, "spam": spam, "reason": reason}
        await asyncio.sleep(1.5)


async def check_one(name, semaphore, progress, task_id, api_id, api_hash):
    async with semaphore:
        try:
            result = await inspect_session(name, api_id, api_hash)
        except Exception as error:
            result = {
                "name": name,
                "status": "error",
                **empty_result(),
                "spam": "-",
                "reason": error_text(error),
            }
        if result.pop("keep_source", False):
            progress.update(task_id, advance=1)
            return result
        try:
            stored_name, warning = await asyncio.to_thread(move_session, name, result["status"])
            if stored_name != name or warning:
                messages = [result["reason"]] if result["reason"] else []
                if stored_name != name:
                    messages.append(f"Saved as {stored_name}.session")
                if warning:
                    messages.append(warning)
                result["reason"] = "; ".join(messages)
            result["name"] = stored_name
        except (OSError, ValueError) as error:
            result["status"] = "error"
            result["reason"] = f"Could not sort session: {error_text(error)}"
        progress.update(task_id, advance=1)
        return result


def print_results(results):
    table = Table(title="Results", show_header=True, header_style="bold")
    table.add_column("Account", overflow="ellipsis", max_width=32)
    table.add_column("Status", no_wrap=True)
    table.add_column("Spam", overflow="fold", max_width=28)
    table.add_column("Reason", overflow="fold", max_width=48)
    colors = {"valid": "green", "2fa": "magenta", "invalid": "red", "banned": "red", "deactivated": "red"}
    for result in results:
        account = f"{result['name']}.session"
        if result["username"] != "-":
            account += f" @{result['username']}"
        table.add_row(
            Text(account),
            Text(result["status"].upper(), style=colors.get(result["status"], "yellow")),
            Text(result["spam"]),
            Text(result["reason"]),
        )
    console.print(table)


def report_field(value):
    return re.sub(r"[\r\n|]", " ", str(value))


def write_report(results):
    columns = (
        "file", "id", "username", "first", "last", "phone", "premium", "bot", "spam", "status", "reason"
    )
    lines = [" | ".join(columns)]
    for result in results:
        row = [f"{result['name']}.session"] + [result[key] for key in columns[1:]]
        lines.append(" | ".join(report_field(value) for value in row))
    write_private(REPORT_PATH, "\n".join(lines) + "\n")


def telegram_send(token, chat_id, message):
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message},
            timeout=10,
        )
        response.raise_for_status()
        return response.json().get("ok") is True
    except (requests.RequestException, ValueError):
        return False


def thread_count(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return DEFAULT_THREADS
    return number if 1 <= number <= MAX_THREADS else DEFAULT_THREADS


async def run_checker(threads):
    ensure_dirs()
    names = session_files()
    if not names:
        console.print("[bold red]No .session files found in ./sessions[/bold red]")
        return None

    try:
        api_id, api_hash = api_credentials()
    except ValueError as error:
        console.print(Text(str(error), style="red"))
        return None

    console.print(f"[bold]Loaded {len(names)} sessions[/bold]\n")
    semaphore = asyncio.Semaphore(thread_count(threads))
    started = time.monotonic()
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Checking", total=len(names))
        results = await asyncio.gather(
            *(check_one(name, semaphore, progress, task_id, api_id, api_hash) for name in names)
        )

    elapsed = time.monotonic() - started
    print_results(results)
    try:
        write_report(results)
        console.print(f"[bold]Report saved to:[/bold] {REPORT_PATH}")
    except OSError as error:
        console.print(Text(f"Could not save report: {error_text(error)}", style="red"))

    without_2fa = sum(result["status"] == "valid" for result in results)
    two_fa = sum(result["status"] == "2fa" for result in results)
    invalid = sum(
        result["status"] in ("invalid", "banned", "deactivated", "login_required")
        for result in results
    )
    retry = len(results) - without_2fa - two_fa - invalid
    valid = without_2fa + two_fa
    rate = len(results) / elapsed * 60 if elapsed > 0 else 0.0
    console.print(
        f"\n[bold]Summary:[/bold] [green]{valid} valid[/green] "
        f"([magenta]{two_fa} with 2FA[/magenta]) | [red]{invalid} invalid[/red] | "
        f"[yellow]{retry} retry[/yellow]"
    )
    console.print(f"[bold]Speed:[/bold] {rate:.1f} acc/min  |  [bold]Time:[/bold] {elapsed:.1f}s")
    return {
        "valid": valid,
        "two_fa": two_fa,
        "invalid": invalid,
        "retry": retry,
        "rate": rate,
        "elapsed": elapsed,
    }


async def action_run(config):
    summary = await run_checker(thread_count(config.get("threads")))
    if not summary:
        return
    token = config.get("bot_token")
    chat_id = config.get("chat_id")
    if token and chat_id:
        message = (
            "TG Checker report\n"
            f"Valid: {summary['valid']} (2FA: {summary['two_fa']}) | "
            f"Invalid: {summary['invalid']} | Retry: {summary['retry']}\n"
            f"Speed: {summary['rate']:.1f} acc/min | Time: {summary['elapsed']:.1f}s"
        )
        sent = await asyncio.to_thread(telegram_send, token, chat_id, message)
        console.print(
            "[green]Report sent to Telegram[/green]" if sent else "[yellow]Telegram send failed[/yellow]"
        )


async def action_set_threads(config):
    raw = await questionary.text(
        "Threads (1-50):", default=str(thread_count(config.get("threads")))
    ).ask_async()
    if raw is None:
        return
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if not 1 <= value <= MAX_THREADS:
        console.print("[yellow]Enter a number from 1 to 50.[/yellow]")
        return
    config["threads"] = value
    save_config(config)
    console.print(f"[green]Threads set to {value}[/green]")


async def action_set_bot(config):
    action = await questionary.select(
        "Telegram notifications:", choices=["Configure", "Disable", "Back"]
    ).ask_async()
    if action == "Disable":
        config.pop("bot_token", None)
        config.pop("chat_id", None)
        save_config(config)
        console.print("[green]Telegram notifications disabled.[/green]")
        return
    if action != "Configure":
        return
    token = await questionary.password("Bot token:").ask_async()
    if not token or not token.strip():
        return
    token = token.strip()
    chat_id = await questionary.text("Chat ID:", default=str(config.get("chat_id") or "")).ask_async()
    if chat_id is None:
        return
    chat_id = chat_id.strip()
    if not re.fullmatch(r"-?\d+", chat_id):
        console.print("[yellow]Chat ID must be an integer.[/yellow]")
        return
    config["bot_token"] = token
    config["chat_id"] = chat_id
    save_config(config)
    console.print(f"[green]Bot configured. Chat ID: {chat_id}[/green]")


async def main():
    config = load_config()
    while True:
        choices = [
            "Run Checker",
            f"Threads: {thread_count(config.get('threads'))}",
            f"Telegram Bot: {'configured' if config.get('bot_token') else 'not set'}",
            "Exit",
        ]
        answer = await questionary.select("Select action:", choices=choices, use_arrow_keys=True).ask_async()
        if answer is None or answer == "Exit":
            console.print("[bold cyan]Bye.[/bold cyan]")
            break
        if answer == "Run Checker":
            await action_run(config)
            await questionary.text("Press Enter to continue...").ask_async()
        elif answer.startswith("Threads"):
            await action_set_threads(config)
        elif answer.startswith("Telegram Bot"):
            await action_set_bot(config)


if __name__ == "__main__":
    asyncio.run(main())
