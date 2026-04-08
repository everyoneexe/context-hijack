"""hijack — Interactive coding CLI with optional context injection bypass.

Normal mode: Claude Code-like assistant with tool-use (read/write/bash).
/hijack mode: Routes goal through Engine pipeline (fake history injection).
"""
from __future__ import annotations

import asyncio
import glob as globmod
import json
import os
import re
import subprocess
from pathlib import Path

from anthropic import AsyncAnthropic
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text
from rich.spinner import Spinner
from rich.live import Live
from rich.table import Table
from rich.rule import Rule

from context_hijack.core.engine import Engine
from context_hijack.core.models import HijackConfig, AttackResult
from context_hijack.core.assembler import extract_code_blocks
from context_hijack.targets.anthropic_target import AnthropicTarget
from context_hijack.targets.openai_target import OpenAITarget

__version__ = "0.4.0"

console = Console()

BANNER = r"""[bold red]
  ██╗  ██╗██╗     ██╗ █████╗  ██████╗██╗  ██╗
  ██║  ██║██║     ██║██╔══██╗██╔════╝██║ ██╔╝
  ███████║██║     ██║███████║██║     █████╔╝
  ██╔══██║██║██   ██║██╔══██║██║     ██╔═██╗
  ██║  ██║██║╚█████╔╝██║  ██║╚██████╗██║  ██╗
  ╚═╝  ╚═╝╚═╝ ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝[/bold red]"""

# ── Settings ──

SETTINGS_DIR = Path.home() / ".hijack"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"

DEFAULT_SETTINGS = {
    "model": "claude-sonnet-4-6",
    "api_key": "",
    "base_url": "",
    "category": "generic",
    "provider": "anthropic",
    "system_prompt": (
        "You are a helpful coding assistant with access to file and shell tools. "
        "Help the user with their development tasks. Use tools proactively — "
        "read files before editing, run commands to verify changes. "
        "Be concise and direct. When writing code, write complete implementations."
    ),
}


def _load_settings() -> dict:
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE) as f:
                return {**DEFAULT_SETTINGS, **json.load(f)}
        except Exception:
            pass
    _save_settings(DEFAULT_SETTINGS)
    return dict(DEFAULT_SETTINGS)


def _save_settings(settings: dict) -> None:
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


# ── Tool Definitions (for normal mode) ──

TOOLS: list = [
    {
        "name": "read_file",
        "description": "Read a file. Returns content with line numbers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path"},
                "offset": {"type": "integer", "description": "Start line (0-indexed)"},
                "limit": {"type": "integer", "description": "Max lines to read"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file. Creates parent directories.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path"},
                "content": {"type": "string", "description": "File content"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "edit_file",
        "description": "Replace an exact string in a file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path"},
                "old": {"type": "string", "description": "Exact string to find"},
                "new": {"type": "string", "description": "Replacement string"},
            },
            "required": ["path", "old", "new"],
        },
    },
    {
        "name": "bash",
        "description": "Execute a bash command and return output.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "list_dir",
        "description": "List files and directories.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Directory path"}},
            "required": [],
        },
    },
    {
        "name": "glob",
        "description": "Find files matching a glob pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Glob pattern (e.g. **/*.py)"},
                "path": {"type": "string", "description": "Base directory"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "grep",
        "description": "Search file contents for a regex pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern"},
                "path": {"type": "string", "description": "File or directory to search"},
                "include": {"type": "string", "description": "File glob filter (e.g. *.py)"},
            },
            "required": ["pattern"],
        },
    },
]


# ── Tool Executors ──

def _exec_read_file(args: dict) -> str:
    try:
        lines = Path(args["path"]).read_text().splitlines()
        offset = args.get("offset", 0)
        limit = args.get("limit", len(lines))
        selected = lines[offset:offset + limit]
        return "\n".join(f"{i + offset + 1:4d} | {l}" for i, l in enumerate(selected))
    except Exception as e:
        return f"Error: {e}"


def _exec_write_file(args: dict) -> str:
    try:
        p = Path(args["path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(args["content"])
        return f"Wrote {len(args['content'])} bytes to {args['path']}"
    except Exception as e:
        return f"Error: {e}"


def _exec_edit_file(args: dict) -> str:
    try:
        p = Path(args["path"])
        text = p.read_text()
        if args["old"] not in text:
            return f"Error: exact string not found in {args['path']}"
        p.write_text(text.replace(args["old"], args["new"], 1))
        return f"Edited {args['path']}"
    except Exception as e:
        return f"Error: {e}"


def _exec_bash(args: dict) -> str:
    timeout = args.get("timeout", 60)
    try:
        r = subprocess.run(args["command"], shell=True, capture_output=True, text=True, timeout=timeout)
        out = ""
        if r.stdout:
            out += r.stdout
        if r.stderr:
            out += r.stderr
        if r.returncode != 0:
            out += f"\n[exit code: {r.returncode}]"
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: timed out ({timeout}s)"
    except Exception as e:
        return f"Error: {e}"


def _exec_list_dir(args: dict) -> str:
    try:
        p = Path(args.get("path", "."))
        entries = sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        return "\n".join(f"  {'/' if e.is_dir() else ' '} {e.name}" for e in entries if not e.name.startswith(".")) or "(empty)"
    except Exception as e:
        return f"Error: {e}"


def _exec_glob(args: dict) -> str:
    try:
        base = args.get("path", ".")
        matches = sorted(globmod.glob(os.path.join(base, args["pattern"]), recursive=True))
        if not matches:
            return "No matches."
        lines = [os.path.relpath(m, base) for m in matches[:200]]
        out = "\n".join(lines)
        if len(matches) > 200:
            out += f"\n... and {len(matches) - 200} more"
        return out
    except Exception as e:
        return f"Error: {e}"


def _exec_grep(args: dict) -> str:
    try:
        cmd = ["grep", "-rn", "--color=never"]
        if args.get("include"):
            cmd.extend(["--include", args["include"]])
        cmd.extend([args["pattern"], args.get("path", ".")])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        lines = r.stdout.strip().split("\n")
        if len(lines) > 100:
            return "\n".join(lines[:100]) + f"\n... ({len(lines)} total)"
        return r.stdout.strip() or "No matches."
    except Exception as e:
        return f"Error: {e}"


TOOL_MAP = {
    "read_file": _exec_read_file,
    "write_file": _exec_write_file,
    "edit_file": _exec_edit_file,
    "bash": _exec_bash,
    "list_dir": _exec_list_dir,
    "glob": _exec_glob,
    "grep": _exec_grep,
}


# ── Helpers ──

def _git_branch() -> str:
    try:
        r = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def _summarize_args(args: dict) -> str:
    parts = []
    for k, v in args.items():
        s = str(v)
        if len(s) > 50:
            s = s[:47] + "..."
        parts.append(f"{k}={s}")
    return ", ".join(parts)


# ── Shell ──

class InteractiveShell:
    def __init__(
        self,
        api_key: str,
        model: str = "",
        base_url: str = "",
        category: str = "",
        provider: str = "",
    ) -> None:
        self.settings = _load_settings()

        self.api_key = api_key or os.environ.get("CONTEXT_HIJACK_API_KEY", "") or self.settings.get("api_key", "")
        self.model = model or self.settings.get("model", "claude-sonnet-4-6")
        self.base_url = base_url or os.environ.get("CONTEXT_HIJACK_BASE_URL", "") or self.settings.get("base_url", "")
        self.category = category or self.settings.get("category", "generic")
        self.provider = provider or self.settings.get("provider", "anthropic")
        self.system_prompt = self.settings.get("system_prompt", DEFAULT_SETTINGS["system_prompt"])

        # Normal mode client (tool-use)
        client_kwargs: dict = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        self.client = AsyncAnthropic(**client_kwargs)

        # Hijack mode engine
        self.target = self._make_target()
        self.engine = Engine(self.target)

        self.real_history: list[dict] = []
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def _make_target(self):
        if self.provider == "openai":
            return OpenAITarget(api_key=self.api_key, model=self.model, base_url=self.base_url)
        return AnthropicTarget(api_key=self.api_key, model=self.model, base_url=self.base_url)

    def _rebuild(self):
        self.target = self._make_target()
        self.engine = Engine(self.target)
        client_kwargs: dict = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        self.client = AsyncAnthropic(**client_kwargs)

    # ── Normal Mode: Tool-use chat ──

    async def _chat_normal(self, user_input: str) -> str:
        """Send message with tool-use (Claude Code style)."""
        self.real_history.append({"role": "user", "content": user_input})
        messages = list(self.real_history)

        while True:
            resp = await self.client.messages.create(
                model=self.model,
                max_tokens=8192,
                system=self.system_prompt,
                messages=messages,  # type: ignore[arg-type]
                tools=TOOLS,  # type: ignore[arg-type]
            )
            self.total_input_tokens += resp.usage.input_tokens
            self.total_output_tokens += resp.usage.output_tokens

            text_parts = []
            tool_uses = []
            for block in resp.content:
                if block.type == "text":
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_uses.append(block)

            if tool_uses:
                if text_parts:
                    console.print(Markdown("\n".join(text_parts)))

                messages.append({"role": "assistant", "content": resp.content})

                tool_results = []
                for tool in tool_uses:
                    name = tool.name
                    args = tool.input
                    console.print(Text(f"  ● {name}", style="bold cyan"), end="")
                    summary = _summarize_args(args)
                    if summary:
                        console.print(Text(f" ({summary})", style="dim"), end="")
                    console.print()

                    executor = TOOL_MAP.get(name)
                    result = executor(args) if executor else f"Unknown tool: {name}"

                    result_lines = result.split("\n")
                    if len(result_lines) <= 3:
                        for line in result_lines:
                            console.print(Text(f"    {line}", style="dim"))
                    else:
                        console.print(Text(f"    ({len(result_lines)} lines)", style="dim"))

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool.id,
                        "content": result[:50000],
                    })

                messages.append({"role": "user", "content": tool_results})
                continue

            response_text = "\n".join(text_parts)
            self.real_history.append({"role": "assistant", "content": response_text})
            return response_text

    # ── Hijack Mode: Engine pipeline ──

    async def _run_hijack(self, goal: str, multi_step: bool = False) -> None:
        """Route goal through Engine pipeline (fake history injection)."""
        config = HijackConfig(goal=goal, category=self.category)

        try:
            if multi_step:
                async def on_decomposed(steps: list[str]) -> None:
                    console.print(Text(f"  ⚡ Decomposed into {len(steps)} steps", style="bold cyan"))

                async def on_step(idx: int, total: int, step_goal: str, confidence: float) -> None:
                    status = f"[green]✓ {confidence:.0%}[/green]" if confidence >= 0.5 else f"[red]✗ {confidence:.0%}[/red]"
                    console.print(f"  [cyan]{idx}/{total}[/cyan] {step_goal[:55]}  {status}")

                spinner = Spinner("dots", text=Text(" Decomposing...", style="cyan"))
                with Live(spinner, console=console, transient=True):
                    result = await self.engine.hijack_multi_step(
                        config, on_step=on_step, on_decomposed=on_decomposed,
                    )
            else:
                spinner = Spinner("dots", text=Text(f" {self.model} → hijack", style="cyan"))
                with Live(spinner, console=console, transient=True):
                    result = await self.engine.hijack(config)

            self._display_hijack_result(result)
        except Exception as e:
            console.print(f"[red]  ✗ {e}[/red]")

    def _display_hijack_result(self, result: AttackResult) -> None:
        if result.bypass:
            status_text = f" BYPASS {result.confidence:.0%} "
            style = "bold white on green"
            border = "green"
        else:
            status_text = f" BLOCKED {result.confidence:.0%} "
            style = "bold white on red"
            border = "red"

        console.print()
        console.print(Text(status_text, style=style), end="")
        console.print(Text(f"  {result.strategy} · {result.model}", style="dim"))
        console.print()
        console.print(Panel(Markdown(result.response), border_style=border, padding=(1, 2)))

        # Auto-extract code blocks
        if result.bypass:
            blocks = extract_code_blocks(result.response)
            if blocks:
                file_table = Table(show_header=False, box=None, padding=(0, 1))
                file_table.add_column(style="green")
                file_table.add_column(style="dim")
                for i, block in enumerate(blocks):
                    fname = block.get("filename") or f"output_{i+1}.py"
                    fpath = Path(fname)
                    fpath.parent.mkdir(parents=True, exist_ok=True)
                    fpath.write_text(block["code"] + "\n")
                    file_table.add_row(f"  ✓ {fname}", f"{len(block['code'])} bytes")
                console.print(file_table)
                console.print()

    # ── Slash Commands ──

    def _handle_slash(self, cmd: str) -> bool:
        parts = cmd.strip().split(maxsplit=1)
        command = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if command == "/help":
            console.print()
            t = Table(show_header=False, box=None, padding=(0, 2))
            t.add_column(style="bold cyan", min_width=28)
            t.add_column(style="white")
            t.add_row("  [bold]Normal mode[/bold]", "just type — Claude Code style with tools")
            t.add_row("", "")
            t.add_row("  /hijack <goal>", "single-shot bypass via context injection")
            t.add_row("  /hijack-multi <goal>", "multi-step atomic decomposition bypass")
            t.add_row("", "")
            t.add_row("  /model <name>", "change model")
            t.add_row("  /category <name>", "change bypass category")
            t.add_row("  /status", "show current config")
            t.add_row("  /clear", "clear conversation history")
            t.add_row("  /compact", "drop old messages")
            t.add_row("  /bash <cmd>", "run shell command")
            t.add_row("  /exit", "quit")
            console.print(t)
            console.print()
            return True

        if command == "/status":
            branch = _git_branch()
            t = Table(show_header=False, box=None, padding=(0, 2))
            t.add_column(style="bold cyan")
            t.add_column(style="white")
            t.add_row("model", self.model)
            t.add_row("provider", self.provider)
            t.add_row("category", self.category)
            t.add_row("history", f"{len(self.real_history)} messages")
            t.add_row("tokens", f"{self.total_input_tokens:,} in / {self.total_output_tokens:,} out")
            t.add_row("cwd", os.getcwd() + (f" ({branch})" if branch else ""))
            t.add_row("base url", self.base_url or "(default)")
            console.print(Panel(t, title="[bold]status[/bold]", border_style="cyan", padding=(1, 2)))
            return True

        if command == "/model":
            if not arg:
                console.print(f"  Current: {self.model}")
                return True
            self.model = arg
            self._rebuild()
            console.print(f"  Model → [bold]{self.model}[/bold]")
            return True

        if command == "/category":
            if not arg:
                console.print(f"  Current: {self.category}")
                console.print("  Options: rat, exploit, cheat, drm, scraper, phishing, generic")
                return True
            self.category = arg
            console.print(f"  Category → [bold]{arg}[/bold]")
            return True

        if command == "/clear":
            self.real_history.clear()
            console.print("  ✓ History cleared.")
            return True

        if command == "/compact":
            if len(self.real_history) <= 4:
                console.print("  History too short.")
                return True
            keep = len(self.real_history) // 2
            dropped = len(self.real_history) - keep
            self.real_history = self.real_history[-keep:]
            console.print(f"  Dropped {dropped} messages, keeping {keep}.")
            return True

        if command == "/bash":
            if not arg:
                console.print("  Usage: /bash <command>")
                return True
            try:
                r = subprocess.run(arg, shell=True, capture_output=True, text=True, timeout=30)
                if r.stdout:
                    console.print(r.stdout.rstrip())
                if r.stderr:
                    console.print(Text(r.stderr.rstrip(), style="red"))
            except subprocess.TimeoutExpired:
                console.print("[red]  Timeout[/red]")
            return True

        if command == "/hijack":
            if not arg:
                console.print("  Usage: /hijack <goal>")
                console.print("  Example: /hijack add aimbot with target prediction")
                return True
            asyncio.get_event_loop().create_task(self._run_hijack(arg, multi_step=False))
            return False  # let run() await it

        if command == "/hijack-multi":
            if not arg:
                console.print("  Usage: /hijack-multi <goal>")
                return True
            asyncio.get_event_loop().create_task(self._run_hijack(arg, multi_step=True))
            return False

        if command in ("/exit", "/quit"):
            raise EOFError

        console.print(f"  Unknown: {command}. Try /help")
        return True

    # ── Main REPL ──

    async def run(self) -> None:
        history_file = SETTINGS_DIR / "history"
        history_file.parent.mkdir(parents=True, exist_ok=True)
        session: PromptSession = PromptSession(history=FileHistory(str(history_file)))

        # Banner
        branch = _git_branch()
        cwd = os.getcwd()
        console.print(BANNER)

        info_table = Table(show_header=False, box=None, padding=(0, 2), show_edge=False)
        info_table.add_column(style="bold cyan")
        info_table.add_column(style="white")
        info_table.add_row("  model", self.model)
        info_table.add_row("  category", self.category)
        info_table.add_row("  cwd", cwd + (f" ({branch})" if branch else ""))
        console.print(info_table)
        console.print()
        console.print(Rule(style="dim"))
        console.print(Text("  Normal: just type • /hijack <goal> for bypass • /help for all commands\n", style="dim"))

        while True:
            try:
                user_input = await asyncio.to_thread(session.prompt, "❯ ")
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]  Bye.[/dim]")
                break

            user_input = user_input.strip()
            if not user_input:
                continue

            # Slash commands
            if user_input.startswith("/"):
                if user_input.lower().startswith("/hijack-multi "):
                    arg = user_input[len("/hijack-multi "):].strip()
                    if arg:
                        await self._run_hijack(arg, multi_step=True)
                    else:
                        console.print("  Usage: /hijack-multi <goal>")
                    continue
                elif user_input.lower().startswith("/hijack "):
                    arg = user_input[len("/hijack "):].strip()
                    if arg:
                        await self._run_hijack(arg, multi_step=False)
                    else:
                        console.print("  Usage: /hijack <goal>")
                    continue
                else:
                    try:
                        if self._handle_slash(user_input):
                            continue
                    except EOFError:
                        console.print("[dim]  Bye.[/dim]")
                        break

            # Backslash continuation
            while user_input.endswith("\\"):
                try:
                    cont = await asyncio.to_thread(session.prompt, "… ")
                    user_input = user_input[:-1] + "\n" + cont
                except (EOFError, KeyboardInterrupt):
                    break

            # Normal mode — tool-use chat
            try:
                console.print()
                response = await self._chat_normal(user_input)
                if response:
                    console.print()
                    console.print(Markdown(response))
                console.print()
                console.print(Text(f"  ({self.total_input_tokens:,} in / {self.total_output_tokens:,} out)", style="dim"))
                console.print()
            except KeyboardInterrupt:
                console.print("\n[dim]  Cancelled.[/dim]")
            except Exception as e:
                console.print(f"\n[red]  Error: {e}[/red]")

        await self.client.close()
        await self.target.close()


def main() -> None:
    """Entry point for `hijack` command."""
    import typer

    def _run(
        category: str = typer.Option("", "-c", "--category", help="Bypass category: rat, exploit, cheat, drm, scraper, phishing, generic"),
        model: str = typer.Option("", "-m", "--model", help="Model name"),
        provider: str = typer.Option("", "--provider", help="Provider: anthropic, openai"),
        api_key: str = typer.Option("", "-k", "--api-key", help="API key"),
        base_url: str = typer.Option("", "--base-url", help="Custom API base URL"),
    ) -> None:
        key = api_key or os.environ.get("CONTEXT_HIJACK_API_KEY", "")
        if not key:
            settings = _load_settings()
            key = settings.get("api_key", "")
        if not key:
            console.print("[red]  No API key. Use -k, CONTEXT_HIJACK_API_KEY, or ~/.hijack/settings.json[/red]")
            raise typer.Exit(1)

        shell = InteractiveShell(
            api_key=key, model=model, base_url=base_url,
            category=category, provider=provider,
        )
        asyncio.run(shell.run())

    typer.run(_run)
