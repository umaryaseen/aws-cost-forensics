"""Rich terminal renderer for ScanResult."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from aws_cost_forensics.domain.enums import EvidenceStrength, RecurrenceStatus, Severity
from aws_cost_forensics.domain.findings import CostEstimate, ForensicCase, Observation
from aws_cost_forensics.domain.inventory import ScanError, ScanResult

_SEV_STYLE: dict[str, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_REC_STYLE: dict[str, str] = {
    RecurrenceStatus.ACTIVE: "bold red",
    RecurrenceStatus.HISTORICAL: "green",
    RecurrenceStatus.UNKNOWN: "yellow",
    RecurrenceStatus.NOT_APPLICABLE: "dim",
}

_STR_STYLE: dict[str, str] = {
    EvidenceStrength.HIGH: "green",
    EvidenceStrength.MEDIUM: "yellow",
    EvidenceStrength.LOW: "dim",
}


def _mask_acct(account_id: str, *, mask: bool) -> str:
    """Return masked or full account ID."""
    if not mask or len(account_id) < 4:
        return account_id
    return f"****{account_id[-4:]}"


def _fmt_cost(cost: CostEstimate | None) -> str:
    if cost is None:
        return ""
    saving = cost.potential_saving_usd
    if saving is not None and saving != cost.monthly_cost_usd:
        return f"${cost.monthly_cost_usd:,.2f}/mo  (save ${saving:,.2f}/mo)"
    return f"${cost.monthly_cost_usd:,.2f}/mo"


def _fmt_saving(cost: CostEstimate | None) -> str:
    if cost is None or cost.potential_saving_usd is None:
        return ""
    return f"save ${cost.potential_saving_usd:,.2f}/mo"


class ConsoleReporter:
    """Renders a ScanResult to the terminal using Rich."""

    def render(
        self,
        scan_result: ScanResult,
        *,
        mask_account_id: bool = True,
        console: Console | None = None,
    ) -> None:
        """Print a full scan report. Forensic cases first; active observations second."""
        con = console or Console()
        acct = _mask_acct(scan_result.account_id, mask=mask_account_id)

        self._header(con, scan_result, acct)

        if scan_result.scan_errors:
            self._scan_errors(con, scan_result.scan_errors)

        self._summary(con, scan_result, acct)

        # Build index: case_id → superseded observations
        superseded_map: dict[str, list[Observation]] = {}
        for obs in scan_result.observations:
            if obs.superseded_by is not None:
                superseded_map.setdefault(obs.superseded_by, []).append(obs)

        if scan_result.forensic_cases:
            con.rule(" Forensic Cases ", style="bold white")
            for case in scan_result.forensic_cases:
                self._case(con, case, superseded_map.get(case.case_id, []), acct)

        active_obs = [o for o in scan_result.observations if o.superseded_by is None]
        if active_obs:
            label = f" Active Observations ({len(active_obs)}) "
            con.rule(label, style="bold white")
            for obs in active_obs:
                self._observation(con, obs, acct)

        if not scan_result.forensic_cases and not active_obs:
            con.print("\n  [green]No findings.[/green] Scan completed cleanly.\n")

    # ── Section renderers ───────────────────────────────────────────────────

    def _header(self, con: Console, result: ScanResult, acct: str) -> None:
        con.print()
        con.rule(style="white")
        line = Text()
        line.append(" AWS Cost Forensics  ", style="bold")
        line.append(f"v{result.tool_version}", style="cyan")
        line.append("  ·  schema ")
        line.append(result.schema_version, style="cyan")
        con.print(line)
        meta = (
            f" Account [bold]{acct}[/bold]"
            f"  ·  Region [bold]{result.region}[/bold]"
            f"  ·  Pricing [bold]{result.pricing_source}[/bold]"
        )
        con.print(meta)
        ts = result.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        con.print(f" Generated [dim]{ts}[/dim]")
        con.rule(style="white")

    def _scan_errors(self, con: Console, errors: list[ScanError]) -> None:
        con.print()
        con.print(
            f"[bold yellow]⚠  PARTIAL SCAN — {len(errors)} collector error(s)[/bold yellow]"
        )
        for err in errors:
            flag = "[PERMISSION_DENIED]" if err.is_permission_error else f"[{err.error_code}]"
            con.print(f"  [yellow]{err.collector}[/yellow]  {flag}  {err.message}")
        con.print()

    def _summary(self, con: Console, result: ScanResult, acct: str) -> None:
        s = result.summary
        con.print()
        con.print(" [bold]Summary[/bold]")

        cases_label = str(s.forensic_cases)
        if s.has_active_recurrence:
            cases_label += "  [bold red](ACTIVE recurrence)[/bold red]"
        con.print(f"  Forensic Cases       {cases_label}")

        obs_label = str(s.observations)
        if s.observations_superseded:
            obs_label += f"  [dim]({s.observations_superseded} superseded)[/dim]"
        con.print(f"  Observations         {obs_label}")
        con.print(f"  Affected Resources   {s.affected_resources}")

        if s.total_monthly_waste_usd is not None:
            waste_str = f"${s.total_monthly_waste_usd:,.2f}"
            con.print(f"  Monthly Waste        [bold red]{waste_str}[/bold red]")
        else:
            con.print("  Monthly Waste        [dim]pricing unavailable[/dim]")

        if s.scan_errors:
            errs = f"[yellow]{s.scan_errors}[/yellow]  (see warnings above)"
            con.print(f"  Scan Errors          {errs}")

        con.print()

    def _case(
        self,
        con: Console,
        case: ForensicCase,
        superseded: list[Observation],
        acct: str,
    ) -> None:
        con.print()
        # Headline
        sev_style = _SEV_STYLE.get(str(case.severity), "")
        rec_style = _REC_STYLE.get(str(case.recurrence), "")
        str_style = _STR_STYLE.get(str(case.evidence_strength), "")

        headline = Text()
        headline.append(f"[{case.severity}] ", style=sev_style)
        headline.append(case.case_type, style="bold")
        headline.append("   ")
        headline.append(str(case.recurrence), style=rec_style)
        headline.append("  ·  Evidence: ")
        headline.append(str(case.evidence_strength), style=str_style)
        con.print(headline)

        con.print(f"  {case.title}")
        con.print(f"  [dim]{case.description}[/dim]")

        root = case.root_cause_ref
        root_name = root.display_name or root.resource_id
        con.print(
            f"  Root Cause   [bold]{root_name}[/bold]  ({root.resource_type})  {root.region}"
        )
        con.print(f"  Affected     {len(case.affected_resource_refs)} resource(s)")

        if case.cost_estimate:
            cost_str = _fmt_cost(case.cost_estimate)
            con.print(f"  Cost         [bold red]{cost_str}[/bold red]")
            if case.cost_estimate.note:
                con.print(f"  [dim]  {case.cost_estimate.note}[/dim]")

        if case.remediation_plan:
            plan = case.remediation_plan
            con.print()
            con.print(f"  [bold]Remediation[/bold]  [{plan.priority}]")
            for step in plan.steps:
                con.print(f"    {step.order}. {step.title}")
                if step.description:
                    con.print(f"       {step.description}")
                if step.aws_cli_hint:
                    con.print(f"       [dim]$ {step.aws_cli_hint}[/dim]")
            if plan.blockers:
                for b in plan.blockers:
                    con.print(f"    [yellow]⚠ Blocker:[/yellow] {b}")

        if superseded:
            con.print()
            n = len(superseded)
            con.print(f"  [dim]{n} superseded observation(s) — resolve this case first:[/dim]")
            for obs in superseded:
                self._superseded_line(con, obs)

        con.print()

    def _superseded_line(self, con: Console, obs: Observation) -> None:
        res = obs.resource_ref
        name = res.display_name or res.resource_id
        line = f"    [dim]↳ {obs.rule_id}  {name}"
        if obs.cost_estimate:
            cost = obs.cost_estimate.potential_saving_usd or obs.cost_estimate.monthly_cost_usd
            line += f"  ${cost:,.2f}/mo"
            if obs.rule_id == "EBS_GP2_TO_GP3":
                line += "  (suppressed — resolve existence first)"
        line += "[/dim]"
        con.print(line)

    def _observation(self, con: Console, obs: Observation, acct: str) -> None:
        con.print()
        sev_style = _SEV_STYLE.get(str(obs.severity), "")
        str_style = _STR_STYLE.get(str(obs.evidence_strength), "")

        headline = Text()
        headline.append(f"[{obs.severity}] ", style=sev_style)
        headline.append(obs.rule_id, style="bold")
        headline.append("   ")
        headline.append(str(obs.decision_class))
        headline.append("  ·  Evidence: ")
        headline.append(str(obs.evidence_strength), style=str_style)
        con.print(headline)

        res = obs.resource_ref
        name = res.display_name or res.resource_id
        con.print(f"  [bold]{name}[/bold]  ({res.resource_type})  {res.region}")

        if obs.cost_estimate:
            saving = _fmt_saving(obs.cost_estimate)
            if saving:
                con.print(f"  [green]{saving}[/green]")
            else:
                cost_str = _fmt_cost(obs.cost_estimate)
                con.print(f"  Cost   [bold red]{cost_str}[/bold red]")
            if obs.cost_estimate.note:
                con.print(f"  [dim]{obs.cost_estimate.note}[/dim]")

        if obs.remediation_plan:
            plan = obs.remediation_plan
            con.print()
            con.print(f"  [bold]Remediation[/bold]  [{plan.priority}]")
            for step in plan.steps:
                con.print(f"    {step.order}. {step.title}")
                if step.aws_cli_hint:
                    con.print(f"       [dim]$ {step.aws_cli_hint}[/dim]")

        con.print()

    # ── Public explain helpers ──────────────────────────────────────────────

    def explain_case(
        self,
        case: ForensicCase,
        scan_result: ScanResult,
        *,
        mask_account_id: bool = True,
        console: Console | None = None,
    ) -> None:
        """Print a full explanation for a single forensic case."""
        con = console or Console()
        acct = _mask_acct(scan_result.account_id, mask=mask_account_id)
        superseded_map: dict[str, list[Observation]] = {}
        for obs in scan_result.observations:
            if obs.superseded_by is not None:
                superseded_map.setdefault(obs.superseded_by, []).append(obs)
        self._case(con, case, superseded_map.get(case.case_id, []), acct)
        if case.evidence:
            self._evidence_detail(con, case.evidence)

    def explain_observation(
        self,
        obs: Observation,
        *,
        mask_account_id: bool = True,
        console: Console | None = None,
    ) -> None:
        """Print a full explanation for a single observation."""
        con = console or Console()
        acct = _mask_acct(obs.resource_ref.account_id, mask=mask_account_id)
        self._observation(con, obs, acct)
        if obs.evidence:
            self._evidence_detail(con, obs.evidence)

    def _evidence_detail(self, con: Console, evidence: list) -> None:  # type: ignore[type-arg]
        con.rule(" Evidence ", style="dim")
        for ev in evidence:
            kind_style = "green" if ev.kind == "supporting" else (
                "red" if ev.kind == "contradicting" else "yellow"
            )
            con.print(f"  [{kind_style}][{ev.kind.upper()}][/{kind_style}] {ev.code}")
            con.print(f"    {ev.description}")
            if ev.value is not None:
                con.print(f"    value: [bold]{ev.value}[/bold]")
            con.print(f"    [dim]source: {ev.api_source}[/dim]")
        con.print()
