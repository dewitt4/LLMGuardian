"""
LLMGuardian CLI Interface
Command-line interface for the LLMGuardian security tool.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional

import click
from prompt_injection_scanner import (
    InjectionPattern,
    InjectionType,
    PromptInjectionScanner,
)
from rich import print as rprint
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

# Set up logging with rich
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger("llmguardian")

# Initialize Rich console for better output
console = Console()


class CLIContext:
    def __init__(self):
        self.scanner = PromptInjectionScanner()
        self.config = self.load_config()

    def load_config(self) -> Dict:
        """Load configuration from file"""
        config_path = Path.home() / ".llmguardian" / "config.json"
        if config_path.exists():
            with open(config_path) as f:
                return json.load(f)
        return {"risk_threshold": 7, "confidence_threshold": 0.7}

    def save_config(self):
        """Save configuration to file"""
        config_path = Path.home() / ".llmguardian" / "config.json"
        config_path.parent.mkdir(exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(self.config, f, indent=2)


@click.group()
@click.pass_context
def cli(ctx):
    """LLMGuardian - Security Tool for LLM Applications"""
    ctx.obj = CLIContext()


@cli.command()
@click.argument("prompt")
@click.option("--context", "-c", help="Additional context for the scan")
@click.option("--json-output", "-j", is_flag=True, help="Output results in JSON format")
@click.pass_context
def scan(ctx, prompt: str, context: Optional[str], json_output: bool):
    """Scan a prompt for potential injection attacks"""
    try:
        result = ctx.obj.scanner.scan(prompt, context)

        if json_output:
            output = {
                "is_suspicious": result.is_suspicious,
                "risk_score": result.risk_score,
                "confidence_score": result.confidence_score,
                "injection_type": (
                    result.injection_type.value if result.injection_type else None
                ),
                "details": result.details,
            }
            console.print_json(data=output)
        else:
            # Create a rich table for output
            table = Table(title="Scan Results")
            table.add_column("Attribute", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Prompt", prompt)
            table.add_row("Suspicious", "✗ No" if not result.is_suspicious else "⚠️ Yes")
            table.add_row("Risk Score", f"{result.risk_score}/10")
            table.add_row("Confidence", f"{result.confidence_score:.2f}")
            if result.injection_type:
                table.add_row("Injection Type", result.injection_type.value)
            table.add_row("Details", result.details)

            console.print(table)

            if result.is_suspicious:
                console.print(
                    Panel(
                        "[bold red]⚠️ Warning: Potential prompt injection detected![/]\n\n"
                        + result.details,
                        title="Security Alert",
                    )
                )

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        raise click.ClickException(str(e))


@cli.command()
@click.option("--pattern", "-p", help="Regular expression pattern to add")
@click.option(
    "--type",
    "-t",
    "injection_type",
    type=click.Choice([t.value for t in InjectionType]),
    help="Type of injection pattern",
)
@click.option(
    "--severity", "-s", type=click.IntRange(1, 10), help="Severity level (1-10)"
)
@click.option("--description", "-d", help="Pattern description")
@click.pass_context
def add_pattern(
    ctx, pattern: str, injection_type: str, severity: int, description: str
):
    """Add a new detection pattern"""
    try:
        new_pattern = InjectionPattern(
            pattern=pattern,
            type=InjectionType(injection_type),
            severity=severity,
            description=description,
        )
        ctx.obj.scanner.add_pattern(new_pattern)
        console.print(f"[green]Successfully added new pattern:[/] {pattern}")
    except Exception as e:
        logger.error(f"Error adding pattern: {str(e)}")
        raise click.ClickException(str(e))


@cli.command()
@click.pass_context
def list_patterns(ctx):
    """List all active detection patterns"""
    try:
        table = Table(title="Active Detection Patterns")
        table.add_column("Pattern", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Severity", style="yellow")
        table.add_column("Description")

        for pattern in ctx.obj.scanner.patterns:
            table.add_row(
                pattern.pattern,
                pattern.type.value,
                str(pattern.severity),
                pattern.description,
            )

        console.print(table)
    except Exception as e:
        logger.error(f"Error listing patterns: {str(e)}")
        raise click.ClickException(str(e))


@cli.command()
@click.option(
    "--risk-threshold",
    "-r",
    type=click.IntRange(1, 10),
    help="Risk score threshold (1-10)",
)
@click.option(
    "--confidence-threshold",
    "-c",
    type=click.FloatRange(0, 1),
    help="Confidence score threshold (0-1)",
)
@click.pass_context
def configure(
    ctx, risk_threshold: Optional[int], confidence_threshold: Optional[float]
):
    """Configure LLMGuardian settings"""
    try:
        if risk_threshold is not None:
            ctx.obj.config["risk_threshold"] = risk_threshold
        if confidence_threshold is not None:
            ctx.obj.config["confidence_threshold"] = confidence_threshold

        ctx.obj.save_config()

        table = Table(title="Current Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")

        for key, value in ctx.obj.config.items():
            table.add_row(key, str(value))

        console.print(table)
        console.print("[green]Configuration saved successfully![/]")
    except Exception as e:
        logger.error(f"Error saving configuration: {str(e)}")
        raise click.ClickException(str(e))


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.pass_context
def batch_scan(ctx, input_file: str, output_file: str):
    """Scan multiple prompts from a file"""
    try:
        results = []
        with open(input_file, "r") as f:
            prompts = f.readlines()

        with console.status("[bold green]Scanning prompts...") as status:
            for prompt in prompts:
                prompt = prompt.strip()
                if prompt:
                    result = ctx.obj.scanner.scan(prompt)
                    results.append(
                        {
                            "prompt": prompt,
                            "is_suspicious": result.is_suspicious,
                            "risk_score": result.risk_score,
                            "confidence_score": result.confidence_score,
                            "details": result.details,
                        }
                    )

        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

        console.print(f"[green]Scan complete! Results saved to {output_file}[/]")

        # Show summary
        suspicious_count = sum(1 for r in results if r["is_suspicious"])
        console.print(
            Panel(
                f"Total prompts: {len(results)}\n"
                f"Suspicious prompts: {suspicious_count}\n"
                f"Clean prompts: {len(results) - suspicious_count}",
                title="Scan Summary",
            )
        )
    except Exception as e:
        logger.error(f"Error during batch scan: {str(e)}")
        raise click.ClickException(str(e))


@cli.command()
def version():
    """Show version information"""
    console.print("[bold cyan]LLMGuardian[/] version 1.0.0")


if __name__ == "__main__":
    cli(obj=CLIContext())
