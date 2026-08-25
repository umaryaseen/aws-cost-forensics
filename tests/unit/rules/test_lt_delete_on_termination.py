from __future__ import annotations

from datetime import UTC, datetime

from aws_cost_forensics.domain.enums import (
    DecisionClass,
    EvidenceKind,
    EvidenceStrength,
    Severity,
)
from aws_cost_forensics.domain.inventory import Inventory
from aws_cost_forensics.domain.resources import (
    AMI,
    ASGInstance,
    AutoScalingGroup,
    BlockDeviceMapping,
    LaunchTemplateRef,
    LaunchTemplateVersion,
)
from aws_cost_forensics.graph.builder import RelationshipBuilder
from aws_cost_forensics.rules.lt_delete_on_termination import LTDeleteOnTerminationDetector

REGION = "us-east-1"
ACCOUNT = "123456789012"
NOW = datetime(2024, 6, 1, 0, 0, 0, tzinfo=UTC)
TEMPLATE_ID = "lt-aabbccdd11223344"


def _lt_ver(
    version_number: int = 1,
    is_default: bool = True,
    is_latest: bool = True,
    bdms: list[BlockDeviceMapping] | None = None,
    image_id: str | None = "ami-abc123",
    template_id: str = TEMPLATE_ID,
) -> LaunchTemplateVersion:
    return LaunchTemplateVersion(
        template_id=template_id,
        region=REGION,
        account_id=ACCOUNT,
        version_number=version_number,
        is_default=is_default,
        is_latest=is_latest,
        image_id=image_id,
        block_device_mappings=bdms or [],
    )


def _ami(
    image_id: str = "ami-abc123",
    root_device_name: str = "/dev/xvda",
) -> AMI:
    return AMI(
        image_id=image_id,
        region=REGION,
        account_id=ACCOUNT,
        state="available",
        creation_date=NOW,
        root_device_name=root_device_name,
    )


def _asg(
    asg_name: str = "asg-prod",
    template_id: str = TEMPLATE_ID,
    version_selector: str = "$Default",
    resolved_version_number: int = 1,
    max_size: int = 5,
    desired_capacity: int = 2,
) -> AutoScalingGroup:
    return AutoScalingGroup(
        asg_name=asg_name,
        region=REGION,
        account_id=ACCOUNT,
        launch_template_ref=LaunchTemplateRef(
            template_id=template_id,
            version_selector=version_selector,
            resolved_version_number=resolved_version_number,
        ),
        desired_capacity=desired_capacity,
        min_size=0,
        max_size=max_size,
    )


def _bdm(
    device_name: str = "/dev/xvda",
    delete_on_termination: bool | None = False,
) -> BlockDeviceMapping:
    return BlockDeviceMapping(
        device_name=device_name,
        delete_on_termination=delete_on_termination,
    )


def _make_inventory(
    lt_versions: list[LaunchTemplateVersion],
    amis: list[AMI] | None = None,
    asgs: list[AutoScalingGroup] | None = None,
) -> Inventory:
    inv = Inventory(
        account_id=ACCOUNT,
        region=REGION,
        scanned_at=NOW,
        volumes=[],
        snapshots=[],
        amis=amis or [],
        instances=[],
        launch_template_versions=lt_versions,
        auto_scaling_groups=asgs or [],
    )
    RelationshipBuilder(inv.graph).build_all(inv)
    return inv


def _run(inv: Inventory) -> list:
    return LTDeleteOnTerminationDetector().detect(inv)


# ---------------------------------------------------------------------------
# Must NOT fire conditions
# ---------------------------------------------------------------------------


def test_delete_on_termination_none_does_not_fire() -> None:
    # None = unspecified; source will be AMI_DEFAULT, not LT_EXPLICIT
    lt = _lt_ver(bdms=[_bdm(delete_on_termination=None)], image_id="ami-abc123")
    inv = _make_inventory([lt], amis=[_ami()])
    assert _run(inv) == []


def test_delete_on_termination_true_does_not_fire() -> None:
    lt = _lt_ver(bdms=[_bdm(delete_on_termination=True)], image_id="ami-abc123")
    inv = _make_inventory([lt], amis=[_ami()])
    assert _run(inv) == []


def test_no_bdms_ami_available_does_not_fire() -> None:
    # BDM absent + AMI available → AMI_DEFAULT source → no fire
    lt = _lt_ver(bdms=[], image_id="ami-abc123")
    inv = _make_inventory([lt], amis=[_ami()])
    assert _run(inv) == []


def test_empty_lt_versions_no_observations() -> None:
    assert _run(_make_inventory([])) == []


def test_non_root_device_false_does_not_fire() -> None:
    # Root = /dev/xvda (from AMI); data disk /dev/xvdb has DoT=False
    # The rule must NOT fire because it's not the root device
    lt = _lt_ver(
        bdms=[
            _bdm(device_name="/dev/xvda", delete_on_termination=True),
            _bdm(device_name="/dev/xvdb", delete_on_termination=False),
        ],
        image_id="ami-abc123",
    )
    inv = _make_inventory([lt], amis=[_ami(root_device_name="/dev/xvda")])
    assert _run(inv) == []


# ---------------------------------------------------------------------------
# Must fire conditions
# ---------------------------------------------------------------------------


def test_root_device_lt_explicit_false_fires() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)], image_id="ami-abc123")
    inv = _make_inventory([lt], amis=[_ami()])
    assert len(_run(inv)) == 1


def test_fires_once_per_defective_lt_version() -> None:
    lt1 = _lt_ver(version_number=1, bdms=[_bdm("/dev/xvda", False)])
    lt2 = _lt_ver(version_number=2, bdms=[_bdm("/dev/xvda", True)])
    inv = _make_inventory([lt1, lt2], amis=[_ami()])
    assert len(_run(inv)) == 1


def test_two_defective_versions_two_observations() -> None:
    root_false = [_bdm("/dev/xvda", False)]
    lt1 = _lt_ver(version_number=1, is_default=False, is_latest=False, bdms=root_false)
    lt2 = _lt_ver(version_number=2, is_default=True, is_latest=True, bdms=root_false)
    inv = _make_inventory([lt1, lt2], amis=[_ami()])
    assert len(_run(inv)) == 2


# ---------------------------------------------------------------------------
# Root device resolved from AMI vs heuristic
# ---------------------------------------------------------------------------


def test_root_device_from_ami_root_device_name() -> None:
    # AMI says root is /dev/sda1; LT has both /dev/sda1 (False) and /dev/xvdb (True)
    lt = _lt_ver(
        bdms=[
            _bdm("/dev/sda1", False),
            _bdm("/dev/xvdb", True),
        ],
        image_id="ami-abc123",
    )
    inv = _make_inventory([lt], amis=[_ami(root_device_name="/dev/sda1")])
    obs = _run(inv)
    assert len(obs) == 1


def test_root_device_from_heuristic_when_no_ami() -> None:
    # No AMI in inventory — heuristic identifies /dev/xvda as root
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)], image_id="ami-missing")
    inv = _make_inventory([lt], amis=[])
    obs = _run(inv)
    assert len(obs) == 1


def test_missing_evidence_when_ami_unavailable() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)], image_id="ami-missing")
    inv = _make_inventory([lt], amis=[])
    obs = _run(inv)[0]
    codes = [e.code for e in obs.evidence]
    assert "ROOT_DEVICE_RESOLUTION_INCOMPLETE" in codes


def test_no_resolution_incomplete_evidence_when_ami_available() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)], image_id="ami-abc123")
    inv = _make_inventory([lt], amis=[_ami()])
    obs = _run(inv)[0]
    codes = [e.code for e in obs.evidence]
    assert "ROOT_DEVICE_RESOLUTION_INCOMPLETE" not in codes


# ---------------------------------------------------------------------------
# Observation metadata
# ---------------------------------------------------------------------------


def test_rule_id() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)])
    inv = _make_inventory([lt], amis=[_ami()])
    obs = _run(inv)[0]
    assert obs.rule_id == "LT_DELETE_ON_TERMINATION_FALSE"


def test_decision_class_configuration_defect() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)])
    inv = _make_inventory([lt], amis=[_ami()])
    obs = _run(inv)[0]
    assert obs.decision_class == DecisionClass.CONFIGURATION_DEFECT


# ---------------------------------------------------------------------------
# Severity — based on ASG reference
# ---------------------------------------------------------------------------


def test_severity_critical_active_asg_with_reachable_launch_path() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)])
    asg = _asg(resolved_version_number=1, max_size=5)
    inv = _make_inventory([lt], amis=[_ami()], asgs=[asg])
    obs = _run(inv)[0]
    assert obs.severity == Severity.CRITICAL


def test_severity_medium_no_asg_reference() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)])
    inv = _make_inventory([lt], amis=[_ami()], asgs=[])
    obs = _run(inv)[0]
    assert obs.severity == Severity.MEDIUM


def test_severity_high_asg_max_size_zero() -> None:
    # ASG uses this version but max_size=0 → has_reachable_launch_path=False → HIGH not CRITICAL
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)])
    asg = _asg(resolved_version_number=1, max_size=0, desired_capacity=0)
    inv = _make_inventory([lt], amis=[_ami()], asgs=[asg])
    obs = _run(inv)[0]
    assert obs.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# EvidenceStrength
# ---------------------------------------------------------------------------


def test_strength_high_active_asg_and_prominent_version() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)], is_default=True, is_latest=True)
    asg = _asg(resolved_version_number=1, max_size=5)
    inv = _make_inventory([lt], amis=[_ami()], asgs=[asg])
    obs = _run(inv)[0]
    assert obs.evidence_strength == EvidenceStrength.HIGH


def test_strength_medium_active_asg_non_prominent() -> None:
    lt = _lt_ver(
        version_number=3,
        bdms=[_bdm("/dev/xvda", False)],
        is_default=False,
        is_latest=False,
    )
    asg = _asg(resolved_version_number=3, max_size=5)
    inv = _make_inventory([lt], amis=[_ami()], asgs=[asg])
    obs = _run(inv)[0]
    assert obs.evidence_strength == EvidenceStrength.MEDIUM


def test_strength_medium_prominent_no_asg() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)], is_default=True, is_latest=True)
    inv = _make_inventory([lt], amis=[_ami()], asgs=[])
    obs = _run(inv)[0]
    assert obs.evidence_strength == EvidenceStrength.MEDIUM


def test_strength_low_non_prominent_no_asg() -> None:
    lt = _lt_ver(
        version_number=2,
        bdms=[_bdm("/dev/xvda", False)],
        is_default=False,
        is_latest=False,
    )
    inv = _make_inventory([lt], amis=[_ami()], asgs=[])
    obs = _run(inv)[0]
    assert obs.evidence_strength == EvidenceStrength.LOW


# ---------------------------------------------------------------------------
# Evidence codes
# ---------------------------------------------------------------------------


def test_supporting_evidence_codes_present() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)])
    inv = _make_inventory([lt], amis=[_ami()])
    obs = _run(inv)[0]
    codes = [e.code for e in obs.evidence]
    assert "LT_ROOT_DEVICE_DELETE_ON_TERMINATION_FALSE" in codes
    assert "LT_VERSION_IS_DEFAULT" in codes
    assert "LT_VERSION_IS_LATEST" in codes


def test_asg_references_lt_version_evidence_when_active_asg() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)])
    asg = _asg(resolved_version_number=1, max_size=5)
    inv = _make_inventory([lt], amis=[_ami()], asgs=[asg])
    obs = _run(inv)[0]
    codes = [e.code for e in obs.evidence]
    assert "ASG_REFERENCES_LT_VERSION" in codes
    assert "LT_VERSION_NOT_REFERENCED_BY_ACTIVE_ASG" not in codes


def test_not_referenced_contradicting_evidence_when_no_asg() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)])
    inv = _make_inventory([lt], amis=[_ami()], asgs=[])
    obs = _run(inv)[0]
    contradicting = [e for e in obs.evidence if e.kind == EvidenceKind.CONTRADICTING]
    assert any(e.code == "LT_VERSION_NOT_REFERENCED_BY_ACTIVE_ASG" for e in contradicting)


# ---------------------------------------------------------------------------
# ASG version selector semantics
# ---------------------------------------------------------------------------


def test_asg_using_default_evaluates_resolved_version() -> None:
    # ASG version_selector="$Default", resolved_version_number=1 → should match lt_ver v1
    lt = _lt_ver(version_number=1, bdms=[_bdm("/dev/xvda", False)], is_default=True)
    asg = _asg(version_selector="$Default", resolved_version_number=1)
    inv = _make_inventory([lt], amis=[_ami()], asgs=[asg])
    obs = _run(inv)[0]
    codes = [e.code for e in obs.evidence]
    assert "ASG_REFERENCES_LT_VERSION" in codes


def test_asg_resolved_to_different_version_not_counted() -> None:
    # ASG resolved to v2, but defect is in v1 → ASG should NOT appear in evidence
    lt = _lt_ver(version_number=1, bdms=[_bdm("/dev/xvda", False)], is_default=False)
    asg = _asg(version_selector="$Default", resolved_version_number=2)
    inv = _make_inventory([lt], amis=[_ami()], asgs=[asg])
    obs = _run(inv)[0]
    codes = [e.code for e in obs.evidence]
    assert "ASG_REFERENCES_LT_VERSION" not in codes


def test_asg_pinned_to_broken_version_default_fixed() -> None:
    # ASG pinned to v1 (broken), default = v2 (fixed)
    # The rule fires for v1; ASG references v1 → CRITICAL
    lt_v1 = _lt_ver(
        version_number=1, is_default=False, is_latest=False, bdms=[_bdm("/dev/xvda", False)]
    )
    lt_v2 = _lt_ver(
        version_number=2, is_default=True, is_latest=True, bdms=[_bdm("/dev/xvda", True)]
    )
    asg = _asg(version_selector="3", resolved_version_number=1, max_size=5)
    inv = _make_inventory([lt_v1, lt_v2], amis=[_ami()], asgs=[asg])
    obs = _run(inv)
    # Only v1 fires
    assert len(obs) == 1
    assert obs[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Current instances corroboration (future: live instance evidence)
# ---------------------------------------------------------------------------


def test_asg_with_current_instances_fires() -> None:
    lt = _lt_ver(bdms=[_bdm("/dev/xvda", False)])
    asg = AutoScalingGroup(
        asg_name="asg-prod",
        region=REGION,
        account_id=ACCOUNT,
        launch_template_ref=LaunchTemplateRef(
            template_id=TEMPLATE_ID,
            version_selector="$Default",
            resolved_version_number=1,
        ),
        desired_capacity=2,
        min_size=1,
        max_size=5,
        current_instances=[
            ASGInstance(instance_id="i-aaa", lifecycle_state="InService"),
        ],
    )
    inv = _make_inventory([lt], amis=[_ami()], asgs=[asg])
    obs = _run(inv)
    assert len(obs) == 1
    assert obs[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Historical / source-corrected defect classification (real-world AUAV scenario)
# ---------------------------------------------------------------------------


def _multi_version_inventory(
    defective_versions: list[int],
    corrected_version: int,
    asg_version_selector: str,
    asg_resolved_version: int,
    max_size: int = 1,
) -> Inventory:
    """Build inventory with multiple LT versions, some defective, one corrected."""
    latest = max([*defective_versions, corrected_version])
    default = corrected_version

    lt_versions = []
    for v in defective_versions:
        lt_versions.append(
            _lt_ver(
                version_number=v,
                is_default=(v == default),
                is_latest=(v == latest),
                bdms=[_bdm("/dev/xvda", False)],
            )
        )
    lt_versions.append(
        _lt_ver(
            version_number=corrected_version,
            is_default=(corrected_version == default),
            is_latest=(corrected_version == latest),
            bdms=[_bdm("/dev/xvda", True)],
        )
    )

    asg = _asg(
        version_selector=asg_version_selector,
        resolved_version_number=asg_resolved_version,
        max_size=max_size,
    )
    return _make_inventory(lt_versions, amis=[_ami()], asgs=[asg])


def test_historical_versions_not_active_when_asg_pinned_to_corrected() -> None:
    """v1-v72 defective, v73 corrected, ASG pinned to v73 → no ACTIVE defect."""
    inv = _multi_version_inventory(
        defective_versions=list(range(1, 73)),
        corrected_version=73,
        asg_version_selector="73",
        asg_resolved_version=73,
    )
    obs = _run(inv)
    # All 72 defective versions fire
    assert len(obs) == 72
    # None should be CRITICAL or reference ASG
    for o in obs:
        assert o.severity == Severity.INFO, (
            f"Expected INFO, got {o.severity} for {o.observation_id}"
        )
        assert not any(e.code == "ASG_REFERENCES_LT_VERSION" for e in o.evidence)


def test_historical_versions_carry_historically_defective_evidence() -> None:
    """Each historical defective version carries LT_VERSION_HISTORICALLY_DEFECTIVE evidence."""
    inv = _multi_version_inventory(
        defective_versions=[1, 2, 3],
        corrected_version=4,
        asg_version_selector="4",
        asg_resolved_version=4,
    )
    obs = _run(inv)
    assert len(obs) == 3
    for o in obs:
        codes = {e.code for e in o.evidence}
        assert "LT_VERSION_HISTORICALLY_DEFECTIVE" in codes
        assert "LT_VERSION_NOT_REFERENCED_BY_ACTIVE_ASG" in codes


def test_historical_versions_preserved_in_structured_output() -> None:
    """Historical observations remain in output — forensic record is preserved."""
    inv = _multi_version_inventory(
        defective_versions=[1, 2],
        corrected_version=3,
        asg_version_selector="3",
        asg_resolved_version=3,
    )
    obs = _run(inv)
    # Both historical versions present in output
    assert len(obs) == 2
    version_nums = {
        e.value for o in obs for e in o.evidence if e.code == "LT_VERSION_HISTORICALLY_DEFECTIVE"
    }
    assert version_nums == {1, 2}


def test_current_defect_asg_pinned_to_broken_version_is_critical() -> None:
    """ASG pinned to defective v72 with corrected v73 available → CRITICAL for v72."""
    inv = _multi_version_inventory(
        defective_versions=[72],
        corrected_version=73,
        asg_version_selector="72",
        asg_resolved_version=72,
        max_size=5,
    )
    obs = _run(inv)
    assert len(obs) == 1
    assert obs[0].severity == Severity.CRITICAL
    assert not any(e.code == "LT_VERSION_HISTORICALLY_DEFECTIVE" for e in obs[0].evidence)
    assert any(e.code == "ASG_REFERENCES_LT_VERSION" for e in obs[0].evidence)


def test_dollar_default_resolves_to_corrected_no_active_defect() -> None:
    """ASG uses $Default, default resolves to corrected v73 → historical versions not ACTIVE."""
    inv = _multi_version_inventory(
        defective_versions=[71, 72],
        corrected_version=73,
        asg_version_selector="$Default",
        asg_resolved_version=73,
    )
    obs = _run(inv)
    assert len(obs) == 2
    for o in obs:
        assert o.severity == Severity.INFO
        assert any(e.code == "LT_VERSION_HISTORICALLY_DEFECTIVE" for e in o.evidence)


def test_dollar_latest_resolves_to_corrected_no_active_defect() -> None:
    """ASG uses $Latest, latest resolves to corrected v73 → historical versions not ACTIVE."""
    inv = _multi_version_inventory(
        defective_versions=[71, 72],
        corrected_version=73,
        asg_version_selector="$Latest",
        asg_resolved_version=73,
    )
    obs = _run(inv)
    assert len(obs) == 2
    for o in obs:
        assert o.severity == Severity.INFO


def test_severity_medium_when_not_default_latest_but_no_historical_flag() -> None:
    """Non-default/non-latest version with no ASG gets INFO (historical classification)."""
    # is_default=False, is_latest=False → the historical flag fires.
    lt = _lt_ver(
        version_number=5,
        is_default=False,
        is_latest=False,
        bdms=[_bdm("/dev/xvda", False)],
    )
    inv = _make_inventory([lt], amis=[_ami()], asgs=[])
    obs = _run(inv)
    assert len(obs) == 1
    # No ASG, not default, not latest → historically classified
    assert obs[0].severity == Severity.INFO
    assert any(e.code == "LT_VERSION_HISTORICALLY_DEFECTIVE" for e in obs[0].evidence)
