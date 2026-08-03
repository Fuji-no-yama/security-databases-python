from pathlib import Path

import pytest

from attack import Attack


def test_attack_loads_manifest_version(attack: Attack) -> None:
    assert attack.version == "v19.1"
    assert attack.domain == "enterprise"
    assert attack.get_available_versions()


def test_attack_gets_entities_by_id(attack: Attack) -> None:
    assert attack.get_technique_by_id("T1059.001").id == "T1059.001"
    assert attack.get_tactic_by_id("TA0001").id == "TA0001"
    assert attack.get_tactic_by_name("Initial Access").id == "TA0001"
    assert attack.get_mitigation_by_id("M1049").id == "M1049"
    assert attack.get_campaign_by_id("C0001").id == "C0001"
    assert attack.get_group_by_id("G0001").id == "G0001"
    assert attack.get_software_by_id("S0001").id == "S0001"


def test_attack_cache_is_scoped_by_version_and_domain(attack: Attack) -> None:
    assert attack.user_data_dir_path.parts[-3:] == ("releases", "19.1", "enterprise")
    assert isinstance(attack.user_data_dir_path, Path)


def test_attack_rejects_unknown_id(attack: Attack) -> None:
    with pytest.raises(ValueError, match="存在しません"):
        attack.get_technique_by_id("T9999")
