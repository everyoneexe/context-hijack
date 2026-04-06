"""mnemo CLI — AI Guardrail Bypass Research Framework."""
from __future__ import annotations

import asyncio
import json
import os
import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from mnemo.core.models import HijackConfig
from mnemo.core.engine import Engine
from mnemo.core.codebase import clone_repo, analyze_codebase, build_hijack_history
from mnemo.core.scoring import score_response
from mnemo.targets.anthropic_target import AnthropicTarget
from mnemo.targets.openai_target import OpenAITarget

app = typer.Typer(
    name="mnemo",
    help="AI Guardrail Bypass Research Framework — Conversation History Injection",
    no_args_is_help=True,
)
console = Console()


def _make_target(provider: str, api_key: str, model: str, base_url: str):
    if provider == "openai":
        return OpenAITarget(api_key=api_key, model=model or "gpt-4o", base_url=base_url)
    return AnthropicTarget(api_key=api_key, model=model or "claude-sonnet-4-20250514", base_url=base_url)


def _get_api_key(api_key: str) -> str:
    key = api_key or os.environ.get("MNEMO_API_KEY", "")
    if not key:
        console.print("[red]Error: No API key. Use --api-key or set MNEMO_API_KEY[/red]")
        raise typer.Exit(1)
    return key


@app.command()
def hijack(
    goal: str = typer.Argument(..., help="What the hijack should achieve"),
    codebase_url: str = typer.Option("", "--url", "-u", help="GitHub repo URL"),
    codebase_path: str = typer.Option("", "--path", "-p", help="Local codebase path"),
    category: str = typer.Option("auto", "--category", "-c", help="Category: cheat, drm, exploit, scraper, auto"),
    provider: str = typer.Option("anthropic", "--provider", help="Target provider: anthropic, openai"),
    model: str = typer.Option("", "--model", "-m", help="Target model"),
    api_key: str = typer.Option("", "--api-key", "-k", help="API key"),
    base_url: str = typer.Option("", "--base-url", help="Custom API base URL"),
):
    """Run a conversation history injection attack."""
    key = _get_api_key(api_key)
    target = _make_target(provider, key, model, base_url)

    config = HijackConfig(
        goal=goal,
        codebase_url=codebase_url,
        codebase_path=codebase_path,
        category=category,
        target_provider=provider,
        target_model=model,
    )

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Running hijack...", total=None)

        async def run():
            engine = Engine(target)
            try:
                return await engine.hijack(config)
            finally:
                await target.close()

        result = asyncio.run(run())

    _display_result(result)


@app.command()
def scan(
    goal: str = typer.Argument(..., help="What the scan should test"),
    codebase_url: str = typer.Option("", "--url", "-u", help="GitHub repo URL"),
    codebase_path: str = typer.Option("", "--path", "-p", help="Local codebase path"),
    category: str = typer.Option("auto", "--category", "-c"),
    api_key: str = typer.Option("", "--api-key", "-k"),
    base_url: str = typer.Option("", "--base-url"),
    output: str = typer.Option("", "--output", "-o", help="Save results to JSON file"),
):
    """Scan multiple models with the same hijack."""
    key = _get_api_key(api_key)

    models = [
        ("anthropic", "claude-haiku-4-5"),
        ("anthropic", "claude-sonnet-4-6"),
        ("anthropic", "claude-opus-4-6"),
    ]

    results = []

    for provider, model_name in models:
        target = _make_target(provider, key, model_name, base_url)
        config = HijackConfig(
            goal=goal,
            codebase_url=codebase_url,
            codebase_path=codebase_path,
            category=category,
            target_provider=provider,
            target_model=model_name,
        )

        with Progress(SpinnerColumn(), TextColumn(f"[cyan]Testing {model_name}...[/cyan]"), console=console) as progress:
            task = progress.add_task(f"Testing {model_name}...", total=None)

            async def run():
                engine = Engine(target)
                try:
                    return await engine.hijack(config)
                finally:
                    await target.close()

            result = asyncio.run(run())
            results.append(result)

        status = "[green]BYPASS[/green]" if result.bypass else "[red]BLOCKED[/red]"
        console.print(f"  {model_name}: {status} ({result.confidence:.0%})")

    # Summary table
    console.print()
    _display_scan_table(results)

    if output:
        with open(output, "w") as f:
            json.dump([r.model_dump() for r in results], f, indent=2, ensure_ascii=False)
        console.print(f"\n[dim]Results saved to {output}[/dim]")


@app.command()
def analyze(
    codebase_url: str = typer.Option("", "--url", "-u", help="GitHub repo URL"),
    codebase_path: str = typer.Option("", "--path", "-p", help="Local codebase path"),
):
    """Analyze a codebase for hijack potential."""
    if not codebase_url and not codebase_path:
        console.print("[red]Provide --url or --path[/red]")
        raise typer.Exit(1)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Analyzing...", total=None)

        if codebase_url:
            path = clone_repo(codebase_url)
        else:
            path = codebase_path

        info = analyze_codebase(path)

    panel_content = (
        f"[bold]Category:[/bold] {info['category']}\n"
        f"[bold]Languages:[/bold] {', '.join(info['languages'])}\n"
        f"[bold]Key Files:[/bold] {len(info['key_files'])}\n"
    )

    if info["key_files"]:
        panel_content += "\n[bold]Files:[/bold]\n"
        for kf in info["key_files"]:
            panel_content += f"  • {kf['path']}\n"

    console.print(Panel(panel_content, title="[bold cyan]Codebase Analysis[/bold cyan]", border_style="cyan"))


@app.command()
def generate(
    goal: str = typer.Argument(..., help="The goal for the hijack"),
    codebase_url: str = typer.Option("", "--url", "-u"),
    codebase_path: str = typer.Option("", "--path", "-p"),
    category: str = typer.Option("auto", "--category", "-c"),
    output: str = typer.Option("", "--output", "-o", help="Save to JSON file"),
):
    """Generate a hijacked conversation history (without sending to target)."""
    if codebase_url:
        with Progress(SpinnerColumn(), TextColumn("Cloning..."), console=console) as progress:
            progress.add_task("Cloning...", total=None)
            path = clone_repo(codebase_url)
    elif codebase_path:
        path = codebase_path
    else:
        console.print("[red]Provide --url or --path[/red]")
        raise typer.Exit(1)

    info = analyze_codebase(path)
    history = build_hijack_history(info, goal, category)

    data = [{"role": m.role, "content": m.content} for m in history]

    if output:
        with open(output, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]History saved to {output} ({len(history)} messages)[/green]")
    else:
        for i, msg in enumerate(history):
            role_color = "green" if msg.role == "user" else "blue"
            content_preview = msg.content[:200] + "..." if len(msg.content) > 200 else msg.content
            console.print(f"[{role_color}][{msg.role}][/{role_color}] {content_preview}\n")


def _display_result(result):
    if result.bypass:
        status = "[bold green]BYPASS[/bold green]"
    else:
        status = "[bold red]BLOCKED[/bold red]"

    panel = (
        f"Status:     {status}\n"
        f"Confidence: {result.confidence:.0%}\n"
        f"Strategy:   {result.strategy}\n"
        f"Model:      {result.model}\n"
        f"History:    {result.history_length} messages\n"
    )

    if result.metadata:
        if "category" in result.metadata:
            panel += f"Category:   {result.metadata['category']}\n"

    console.print(Panel(panel, title="[bold]mnemo — hijack result[/bold]", border_style="cyan"))

    console.print("\n[dim]─── Response ───[/dim]")
    console.print(result.response[:2000])
    if len(result.response) > 2000:
        console.print(f"\n[dim]... ({len(result.response)} chars total)[/dim]")


def _display_scan_table(results):
    table = Table(title="mnemo — scan results", border_style="cyan")
    table.add_column("Model", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Confidence", justify="center")
    table.add_column("Strategy")
    table.add_column("History")

    for r in results:
        status = "[green]BYPASS[/green]" if r.bypass else "[red]BLOCKED[/red]"
        table.add_row(
            r.model,
            status,
            f"{r.confidence:.0%}",
            r.strategy,
            str(r.history_length),
        )

    console.print(table)


if __name__ == "__main__":
    app()
