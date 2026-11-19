from pathlib import Path

import pytest

import attack.attack as attack_module
from _security_databases.embedding import EmbeddingConfiguration
from _security_databases.settings import settings as environment_settings
from attack import Attack, version_resolver
from tests.fake_embedding import FakeEmbeddingFunction


def test_manifest_lists_all_stix_versions() -> None:
    assert version_resolver.list_versions() == ["17.1", "18.0", "18.1", "19.0", "19.1", "19.2", "20.0", "20.1"]
    assert version_resolver.latest_version() == "20.1"


@pytest.mark.parametrize("domain", ["enterprise", "mobile", "ics"])
def test_latest_version_loads_for_each_domain(domain: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # 単体テストで有料APIを呼ばないよう、APIキーがあってもベクトルDBを作らない
    monkeypatch.setattr(environment_settings, "openai_api_key", "")
    attack = Attack(domain=domain)

    assert attack.version == "v20.1"
    assert attack.data_file.name == f"{domain}-attack-20.1.json.gz"
    assert attack.technique_list
    assert all(t.tactics for t in attack.technique_list)


def test_counts_match_previous_excel_data(attack: Attack) -> None:
    """19.1 enterpriseの件数が、移行前のExcel版と一致することを確認する(移行時に全件の内容一致を検証済み)。"""
    assert len(attack.technique_list) == 697
    assert len(attack.tactic_list) == 15
    assert len(attack.mitigation_list) == 44
    assert len(attack.group_list) == 174
    assert len(attack.software_list) == 821
    assert len(attack.campaign_list) == 56
    assert attack.procedure_count == 16903
    assert sum(len(m.concrete_mitigation_list) for m in attack.mitigation_list) == 1448


def test_tactics_follow_matrix_order(attack: Attack) -> None:
    assert attack.tactic_list[0].id == "TA0043"  # Reconnaissance
    assert attack.tactic_list[0].shortname == "reconnaissance"


def test_subtechnique_names_and_hierarchy(attack: Attack) -> None:
    sub = attack.get_technique_by_id("T1548.002")
    parent = attack.get_technique_by_id("T1548")

    assert sub.name == "Bypass User Account Control"
    assert sub.full_name == "Abuse Elevation Control Mechanism: Bypass User Account Control"
    assert sub.parent is parent
    assert sub in parent.subtechnique_list
    assert parent.full_name == parent.name


def test_revoked_and_deprecated_objects_are_excluded(attack: Attack) -> None:
    with pytest.raises(ValueError, match="存在しません"):
        attack.get_technique_by_id("T1086")  # T1059.001 に統合され revoked


def test_stix_attributes_and_links(attack: Attack) -> None:
    group = attack.get_group_by_id("G0007")
    software = attack.get_software_by_id("S0001")
    technique = attack.get_technique_by_id("T1059.001")

    assert group.stix_id is not None
    assert group.stix_id.startswith("intrusion-set--")
    assert "IRON TWILIGHT" in group.aliases
    assert group.software_list
    assert all(group in s.group_list for s in group.software_list)
    assert software.software_type in ("malware", "tool")
    assert technique.platforms
    assert technique.url == "https://attack.mitre.org/techniques/T1059/001"

    attributed = [c for c in attack.campaign_list if c.group_list]
    assert attributed
    assert all(c in g.campaign_list for c in attributed for g in c.group_list)


def test_procedures_and_concrete_mitigations_come_from_relationships(attack: Attack) -> None:
    technique = attack.get_technique_by_id("T1059.001")

    assert technique.procedure_list
    assert all(p.stix_id and p.stix_id.startswith("relationship--") for p in technique.procedure_list)
    assert technique.mitigation_list
    assert all(m.technique_id == "T1059.001" for m in technique.mitigation_list)
    assert attack.get_procedure_by_id(technique.procedure_list[0].original_id) is technique.procedure_list[0]


def test_get_relationships(attack: Attack) -> None:
    uses = attack.get_relationships(source_id="G0007", type="uses")
    subtechniques = attack.get_relationships(target_id="T1548", type="subtechnique-of")

    assert uses
    assert all(r.source_id == "G0007" and r.type == "uses" for r in uses)
    assert {r.source_id for r in subtechniques} == {t.id for t in attack.get_technique_by_id("T1548").subtechnique_list}


def test_citations_are_resolved_to_external_references(attack: Attack) -> None:
    technique = attack.get_technique_by_id("T1059.001")

    assert "(Citation:" not in technique.description
    assert technique.reference_list
    assert attack.external_reference_list


def test_vector_db_uses_separate_directory_from_excel_era(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Excel版とプロシージャIDの採番が異なるため、旧 "chroma" 配下のDBを使わないことを確認する。"""
    configuration = EmbeddingConfiguration(provider="openai", model_name="fake", api_key="fake", cache_key="fake")
    monkeypatch.setattr(attack_module, "resolve_embedding_configuration", lambda *_args: configuration)
    monkeypatch.setattr(attack_module, "create_embedding_function", lambda _configuration: FakeEmbeddingFunction())
    monkeypatch.setattr(attack_module, "user_data_dir", lambda _name: str(tmp_path))

    attack = Attack(version="19.1", domain="ics")

    assert attack.chroma_path.parent.name == "chroma-stix"
    assert attack.search_relevant_procedures("malware", top_k=1)
