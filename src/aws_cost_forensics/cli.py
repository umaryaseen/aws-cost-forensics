"""AWS Cost Forensics CLI — acf command."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import typer
from rich.console import Console

from aws_cost_forensics.aws.session import ConfigurationError
from aws_cost_forensics.domain.inventory import ScanResult
from aws_cost_forensics.reporters.console import ConsoleReporter
from aws_cost_forensics.reporters.json_reporter import JsonReporter
from aws_cost_forensics.scanner import ScanConfig, Scanner

app = typer.Typer(
    name="acf",
    help="Causal AWS infrastructure cost forensics. Root cause over symptom count.",
    no_args_is_help=True,
)

_PROFILE_HELP = "AWS profile name (overrides ACF_PROFILE env var)"
_REGION_HELP = "AWS region — no default; required if not set in env or config"
_OUTPUT_HELP = "Write scan artifact to this JSON file path"
_STALE_DAYS_HELP = "Age threshold (days) for EBS stale volume rule"


@app.command()
def scan(
    profile: str | None = typer.Option(None, help=_PROFILE_HELP),
    region: str | None = typer.Option(None, help=_REGION_HELP),
    output: str | None = typer.Option(None, help=_OUTPUT_HELP),
    stale_days: int = typer.Option(30, "--stale-days", help=_STALE_DAYS_HELP),
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug-level logging"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable Rich terminal color"),
) -> None:
    """Scan AWS account for cost forensics findings."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)

    config = ScanConfig(profile=profile, region=region, stale_volume_days=stale_days)

    try:
        result = Scanner().run(config)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None
    except Exception as exc:
        typer.echo(f"Fatal error during scan: {exc}", err=True)
        raise typer.Exit(code=1) from None

    con = Console(no_color=no_color)
    ConsoleReporter().render(result, console=con)

    if output:
        out_path = Path(output)
        out_path.write_text(JsonReporter().render(result))
        typer.echo(f"\nScan artifact written to: {output}")

    if result.forensic_cases:
        raise typer.Exit(code=2)


@app.command()
def explain(
    finding_id: str = typer.Argument(help="Case or observation ID to explain"),
    input: str = typer.Option(..., "--input", help="Path to saved scan artifact (JSON)"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable Rich terminal color"),
) -> None:
    """Print full explanation for a forensic case or observation from a saved scan."""
    result = _load_scan(input)
    con = Console(no_color=no_color)
    reporter = ConsoleReporter()

    for case in result.forensic_cases:
        if case.case_id == finding_id:
            reporter.explain_case(case, result, console=con)
            return

    for obs in result.observations:
        if obs.observation_id == finding_id:
            reporter.explain_observation(obs, console=con)
            return

    typer.echo(
        f"Error: no finding with ID '{finding_id}' in {input}.\n"
        "Tip: check case_id or observation_id in the scan artifact.",
        err=True,
    )
    raise typer.Exit(code=1)


@app.command()
def report(
    input: str = typer.Option(..., "--input", help="Path to saved scan artifact (JSON)"),
    format: str = typer.Option("text", "--format", help="Output format: text or json"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable Rich terminal color"),
) -> None:
    """Re-render a full report from a saved scan artifact. Makes no AWS API calls."""
    result = _load_scan(input)

    if format == "json":
        typer.echo(JsonReporter().render(result))
    elif format == "text":
        ConsoleReporter().render(result, console=Console(no_color=no_color))
    else:
        typer.echo(f"Error: unknown format '{format}'. Use 'text' or 'json'.", err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_scan(input_path: str) -> ScanResult:
    """Read and parse a JSON scan artifact; exit with code 1 on failure."""
    path = Path(input_path)
    if not path.exists():
        typer.echo(f"Error: file not found: {input_path}", err=True)
        raise typer.Exit(code=1)
    try:
        return ScanResult.model_validate_json(path.read_text())
    except Exception as exc:
        typer.echo(f"Error: could not parse scan artifact '{input_path}': {exc}", err=True)
        raise typer.Exit(code=1) from None
