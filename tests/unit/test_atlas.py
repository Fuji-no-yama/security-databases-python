import pytest

from atlas import Atlas


def test_atlas_loads_manifest_release(atlas: Atlas) -> None:
    assert atlas.release == "2026.06"
    assert atlas.get_available_versions()
    assert atlas.get_available_legacy_versions()


def test_atlas_gets_entities_by_id(atlas: Atlas) -> None:
    assert atlas.get_technique_by_id("AML.T0000").id == "AML.T0000"
    assert atlas.get_tactic_by_id("AML.TA0000").id == "AML.TA0000"
    assert atlas.get_mitigation_by_id("AML.M0000").id == "AML.M0000"
    assert atlas.get_case_study_by_id("AML.CS0000").id == "AML.CS0000"
    assert atlas.get_case_study_step_by_id("AML.CS0000.S00").id == "AML.CS0000.S00"


def test_atlas_filters_relationships(atlas: Atlas) -> None:
    relationships = atlas.get_relationships(target_id="AML.T0000", type="mitigates")

    assert relationships
    assert all(relationship.target_id == "AML.T0000" for relationship in relationships)
    assert all(relationship.type == "mitigates" for relationship in relationships)


def test_atlas_rejects_unknown_id(atlas: Atlas) -> None:
    with pytest.raises(ValueError, match="見つかりません"):
        atlas.get_technique_by_id("AML.T9999")
