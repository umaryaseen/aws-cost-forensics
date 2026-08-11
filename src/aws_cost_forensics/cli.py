"""AWS Cost Forensics CLI — acf command."""

from __future__ import annotations

import typer

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
    typer.echo("acf scan: not yet implemented")
    raise typer.Exit(code=1)


@app.command()
def explain(
    finding_id: str = typer.Argument(help="Case or observation ID to explain"),
    input: str = typer.Option(..., "--input", help="Path to saved scan artifact (JSON)"),
) -> None:
    """Print full explanation for a forensic case or observation from a saved scan."""
    typer.echo("acf explain: not yet implemented")
    raise typer.Exit(code=1)


@app.command()
def report(
    input: str = typer.Option(..., "--input", help="Path to saved scan artifact (JSON)"),
    format: str = typer.Option("text", "--format", help="Output format: text or json"),
) -> None:
    """Re-render a full report from a saved scan artifact. Makes no AWS API calls."""
    typer.echo("acf report: not yet implemented")
    raise typer.Exit(code=1)
