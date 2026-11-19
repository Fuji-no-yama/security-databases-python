import pytest

from atlas import Atlas
from tests.conftest import build_without_embedding_api


@pytest.fixture(scope="module")
def atlas_6_0() -> Atlas:
    """format-version 6.0.0 の最終リリース。"""
    return build_without_embedding_api(lambda: Atlas(version="2026.09"))


def test_loads_entities_and_software(atlas: Atlas) -> None:
    entity = atlas.get_entity_by_id("AML.E0018")
    software = atlas.get_software_by_id("AML.S0015")

    assert entity.name == "APT28"
    assert entity.entity_type == "Activity Cluster"
    assert entity.attack_reference is not None
    assert entity.attack_reference.id == "G0007"
    assert "Fancy Bear" in [a.name for a in entity.associated_entities]

    assert software.name == "LAMEHUG"
    assert software.software_type == "Malware"
    assert software.aliases == ["PROMPTSTEAL"]
    assert software.attack_reference is not None
    assert software.attack_reference.id == "S9035"


def test_casestudy_attribution_and_reporting(atlas: Atlas) -> None:
    lamehug = atlas.get_case_study_by_id("AML.CS0044")

    assert [(a.entity.id, a.activity_purpose) for a in lamehug.attributions] == [("AML.E0018", "Adversarial Operation")]
    assert lamehug in atlas.get_entity_by_id("AML.E0018").casestudy_list
    assert lamehug.reporter == "CERT-UA"
    # actorは6.1.0で任意項目になり、データに無ければ空文字列のまま(補完しない)
    assert lamehug.actor == ""

    prokyc = atlas.get_case_study_by_id("AML.CS0034")
    assert [e.name for e in prokyc.reported_by] == ["Cato Networks"]


def test_uses_and_implements_relationships(atlas: Atlas) -> None:
    assert [s.id for s in atlas.get_case_study_by_id("AML.CS0035").software_list] == ["AML.S0002"]
    assert [s.id for s in atlas.get_entity_by_id("AML.E0018").software_list] == ["AML.S0015"]

    software = atlas.get_software_by_id("AML.S0015")
    assert {t.id for t in software.technique_list} == {"AML.T0025", "AML.T0037", "AML.T0102"}
    assert software in atlas.get_technique_by_id("AML.T0102").software_list


def test_relationship_activity_purpose(atlas: Atlas) -> None:
    relationships = atlas.get_relationships(source_id="AML.CS0044", type="attributed-to")

    assert len(relationships) == 1
    assert relationships[0].activity_purpose == "Adversarial Operation"


def test_casestudy_dates(atlas: Atlas) -> None:
    cs = atlas.get_case_study_by_id("AML.CS0044")

    assert (cs.start_date, cs.start_date_granularity) == ("2025-06-03", "Month")
    assert (cs.end_date, cs.end_date_granularity) == ("2025-06-03", "Month")


def test_technique_attack_reference(atlas: Atlas) -> None:
    references = [t.attack_reference for t in atlas.technique_list if t.attack_reference is not None]

    assert references
    assert all(r.url.startswith("https://attack.mitre.org/") for r in references)


def test_format_6_0_release_has_no_entities(atlas_6_0: Atlas) -> None:
    cs = atlas_6_0.get_case_study_by_id("AML.CS0044")

    assert atlas_6_0.entity_list == []
    assert atlas_6_0.software_list == []
    assert cs.attributions == []
    assert cs.actor == "APT28"
    with pytest.raises(ValueError, match="見つかりません"):
        atlas_6_0.get_entity_by_id("AML.E0018")


def test_format_6_0_dates_are_read_from_renamed_keys(atlas_6_0: Atlas) -> None:
    cs = atlas_6_0.get_case_study_by_id("AML.CS0044")

    assert (cs.start_date, cs.start_date_granularity) == ("2025-06-03", "Month")
    assert cs.end_date is None
    assert cs.end_date_granularity is None
