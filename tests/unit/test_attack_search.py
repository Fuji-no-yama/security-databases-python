import json
from pathlib import Path

import pytest

import attack.attack as attack_module
from _security_databases.embedding import EmbeddingConfiguration
from attack import Attack, AttackSearchResult
from tests.conftest import build_without_embedding_api
from tests.fake_embedding import FakeEmbeddingFunction


@pytest.fixture(scope="module")
def keyword_attack() -> Attack:
    """Embedding未設定(キーワード検索のみ)の最新enterprise。"""
    return build_without_embedding_api(lambda: Attack(version="20.1", domain="enterprise"))


def _patch_fake_embedding(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeEmbeddingFunction:
    embedding_function = FakeEmbeddingFunction()
    configuration = EmbeddingConfiguration(provider="openai", model_name="fake", api_key="fake", cache_key="fake")
    monkeypatch.setattr(attack_module, "resolve_embedding_configuration", lambda *_args: configuration)
    monkeypatch.setattr(attack_module, "create_embedding_function", lambda _configuration: embedding_function)
    monkeypatch.setattr(attack_module, "user_data_dir", lambda _name: str(tmp_path))
    return embedding_function


@pytest.mark.parametrize(("query", "expected"), [("T1059.001", "T1059.001"), ("t1548.002", "T1548.002"), ("PowerShell", "T1059.001")])
def test_exact_id_or_name_match_ranks_first(keyword_attack: Attack, query: str, expected: str) -> None:
    result = keyword_attack.search_relevant_techniques(query, top_k=3)[0]

    assert isinstance(result, AttackSearchResult)
    assert result.item.id == expected
    assert result.score == 1.0


def test_keyword_search_without_embedding(keyword_attack: Attack) -> None:
    results = keyword_attack.search_relevant_techniques("credential dumping from LSASS memory", top_k=3)

    assert not keyword_attack.vector_search_enabled
    assert results[0].item.id == "T1003.001"
    assert all(0 < r.score < 1 for r in results)


def test_technique_filters(keyword_attack: Attack) -> None:
    def ids(**kwargs: str) -> list[str]:
        return [r.item.id for r in keyword_attack.search_relevant_techniques("credential", top_k=50, **kwargs)]  # ty: ignore[invalid-argument-type]

    assert all(keyword_attack.get_technique_by_id(i).have_parent for i in ids(filter="child"))
    assert not any(keyword_attack.get_technique_by_id(i).have_parent for i in ids(filter="parent"))
    assert all("Linux" in keyword_attack.get_technique_by_id(i).platforms for i in ids(platform="Linux"))
    tactic_ids = ids(tactic_id="TA0006")
    assert tactic_ids
    assert all(any(t.id == "TA0006" for t in keyword_attack.get_technique_by_id(i).tactics) for i in tactic_ids)


def test_search_groups_software_campaigns_mitigations(keyword_attack: Attack) -> None:
    assert keyword_attack.search_relevant_groups("APT28", top_k=1)[0].item.id == "G0007"
    assert keyword_attack.search_relevant_groups("Fancy Bear", top_k=1)[0].item.id == "G0007"  # 別名
    assert keyword_attack.search_relevant_software("Cobalt Strike", top_k=1)[0].item.id == "S0154"
    tools = keyword_attack.search_relevant_software("remote access", top_k=20, software_type="tool")
    assert tools
    assert all(r.item.software_type == "tool" for r in tools)
    assert keyword_attack.search_relevant_campaigns("SolarWinds Compromise", top_k=1)[0].item.id == "C0024"
    assert keyword_attack.search_relevant_mitigations("Multi-factor Authentication", top_k=1)[0].item.id == "M1032"


def test_procedure_search_filters(keyword_attack: Attack) -> None:
    results = keyword_attack.search_relevant_procedures("encoded PowerShell", top_k=10, filter="group", technique_id="T1059.001")

    assert results
    assert all(r.item.parent_type == "group" and r.item.technique_id == "T1059.001" for r in results)


def test_rejects_non_positive_top_k(keyword_attack: Attack) -> None:
    with pytest.raises(ValueError, match="top_k"):
        keyword_attack.search_relevant_groups("x", top_k=0)


def test_text_uses_names_instead_of_citation_numbers(keyword_attack: Attack) -> None:
    group_text = keyword_attack.get_group_by_id("G0007").to_text()

    assert "\nAPT28 is a threat group" in group_text
    assert "(Citation:" not in group_text
    assert "[0]" not in group_text
    # 属性の description は従来どおり引用番号付き
    assert keyword_attack.get_group_by_id("G0007").description.startswith("[")


def test_technique_text_and_dict(keyword_attack: Attack) -> None:
    result = keyword_attack.search_relevant_techniques("T1548.002", top_k=1)[0]

    text = result.to_text(max_related=2)
    assert text.startswith("## T1548.002 Abuse Elevation Control Mechanism: Bypass User Account Control  (score: 1.00)")
    assert "Parent technique: T1548 Abuse Elevation Control Mechanism" in text
    assert "Procedure examples (" in text
    assert "- ... and " in text

    data = result.to_dict()
    assert data["score"] == 1.0
    assert data["full_name"] == "Abuse Elevation Control Mechanism: Bypass User Account Control"
    assert data["parent"] == {"id": "T1548", "name": "Abuse Elevation Control Mechanism"}


def test_procedure_text_links_parent_and_technique(keyword_attack: Attack) -> None:
    procedure = keyword_attack.get_technique_by_id("T1059.001").procedure_list[0]

    assert procedure.parent is not None
    assert procedure.technique is keyword_attack.get_technique_by_id("T1059.001")
    assert procedure.to_text().startswith(f"## {procedure.id} {procedure.parent_name} ({procedure.parent_type}) uses T1059.001")
    assert procedure.to_dict()["technique"] == {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell"}


@pytest.mark.parametrize("domain", ["enterprise", "mobile", "ics"])
def test_all_objects_render_to_json_and_text(domain: str) -> None:
    attack = build_without_embedding_api(lambda: Attack(version="20.1", domain=domain))
    procedures = [p for x in [*attack.campaign_list, *attack.group_list, *attack.software_list] for p in x.procedure_list]
    objects = [
        *attack.technique_list,
        *attack.tactic_list,
        *attack.mitigation_list,
        *attack.group_list,
        *attack.software_list,
        *attack.campaign_list,
        *procedures,
    ]
    for obj in objects:
        json.dumps(obj.to_dict())
        assert obj.to_text().startswith(f"## {obj.id}")


def test_vector_search_builds_index_silently(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    embedding_function = _patch_fake_embedding(monkeypatch, tmp_path)

    attack = Attack(version="20.1", domain="ics")
    results = attack.search_relevant_techniques("manipulation of control", top_k=3)

    assert attack.vector_search_enabled
    assert embedding_function.embedded_count > 0
    assert results
    assert attack.search_relevant_procedures("malware", top_k=1)
    assert attack.search_relevant_groups("threat group", top_k=1)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_vector_index_is_reused_on_next_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_fake_embedding(monkeypatch, tmp_path)
    Attack(version="20.1", domain="ics")
    embedding_function = _patch_fake_embedding(monkeypatch, tmp_path)

    Attack(version="20.1", domain="ics")

    assert embedding_function.embedded_count == 0


def test_verbose_logs_to_stderr_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_fake_embedding(monkeypatch, tmp_path)

    Attack(version="20.1", domain="ics", verbose=True)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "[attack]" in captured.err
