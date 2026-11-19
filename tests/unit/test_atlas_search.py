import json
from collections.abc import Iterator
from pathlib import Path

import pytest

import atlas.atlas as atlas_module
from _security_databases.embedding import EmbeddingConfiguration
from _security_databases.settings import settings as environment_settings
from atlas import Atlas
from tests.fake_embedding import FakeEmbeddingFunction


@pytest.fixture(scope="module")
def keyword_atlas() -> Iterator[Atlas]:
    """Embedding未設定(キーワード検索のみ)のAtlas。"""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(environment_settings, "openai_api_key", "")
        yield Atlas(version="2026.10")


def _patch_fake_embedding(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeEmbeddingFunction:
    embedding_function = FakeEmbeddingFunction()
    configuration = EmbeddingConfiguration(provider="openai", model_name="fake", api_key="fake", cache_key="fake")
    monkeypatch.setattr(atlas_module, "resolve_embedding_configuration", lambda *_args: configuration)
    monkeypatch.setattr(atlas_module, "create_embedding_function", lambda _configuration: embedding_function)
    monkeypatch.setattr(atlas_module, "user_data_dir", lambda _name: str(tmp_path))
    return embedding_function


def test_keyword_search_without_embedding(keyword_atlas: Atlas) -> None:
    results = keyword_atlas.search_relevant_techniques("generate malicious commands with LLM", top_k=3)

    assert not keyword_atlas.vector_search_enabled
    assert results[0].item.id == "AML.T0102"
    assert all(0 < r.score < 1 for r in results)
    assert [r.score for r in results] == sorted((r.score for r in results), reverse=True)


@pytest.mark.parametrize("query", ["AML.T0051", "aml.t0051", "LLM Prompt Injection", "What is AML.T0051?"])
def test_exact_id_or_name_match_ranks_first_with_full_score(keyword_atlas: Atlas, query: str) -> None:
    result = keyword_atlas.search_relevant_techniques(query, top_k=3)[0]

    assert result.item.id == "AML.T0051"
    assert result.score == 1.0


def test_partial_keyword_match_is_below_exact_score(keyword_atlas: Atlas) -> None:
    results = keyword_atlas.search_relevant_techniques("LLMでコマンドを生成する", top_k=3)

    assert all(r.score < 0.5 for r in results)


def test_technique_filters(keyword_atlas: Atlas) -> None:
    def ids(**kwargs: str) -> list[str]:
        return [r.item.id for r in keyword_atlas.search_relevant_techniques("prompt injection", top_k=50, **kwargs)]  # ty: ignore[invalid-argument-type]

    assert all(keyword_atlas.get_technique_by_id(i).have_parent for i in ids(filter="child"))
    assert not any(keyword_atlas.get_technique_by_id(i).have_parent for i in ids(filter="parent"))
    assert all("Agentic AI" in (keyword_atlas.get_technique_by_id(i).platforms or []) for i in ids(platform="Agentic AI"))
    assert all(keyword_atlas.get_technique_by_id(i).maturity == "Realized" for i in ids(maturity="Realized"))
    tactic_ids = ids(tactic_id="AML.TA0005")
    assert tactic_ids
    assert all(any(t.id == "AML.TA0005" for t in keyword_atlas.get_technique_by_id(i).tactics) for i in tactic_ids)


def test_search_mitigations_case_studies_and_steps(keyword_atlas: Atlas) -> None:
    assert keyword_atlas.search_relevant_mitigations("guardrails", top_k=1)[0].item.id == "AML.M0020"

    case_studies = keyword_atlas.search_relevant_case_studies("APT28 LAMEHUG", top_k=3)
    assert case_studies[0].item.id == "AML.CS0044"
    incidents = keyword_atlas.search_relevant_case_studies("prompt injection", top_k=50, casestudy_type="Incident")
    assert incidents
    assert all(r.item.type == "Incident" for r in incidents)

    steps = keyword_atlas.search_relevant_case_study_steps("Qwen Hugging Face malicious commands", top_k=1)
    assert steps[0].item.id == "AML.CS0044.S05"


def test_rejects_non_positive_top_k(keyword_atlas: Atlas) -> None:
    with pytest.raises(ValueError, match="top_k"):
        keyword_atlas.search_relevant_techniques("x", top_k=0)


def test_search_result_to_text_and_dict(keyword_atlas: Atlas) -> None:
    result = keyword_atlas.search_relevant_techniques("AML.T0102", top_k=1)[0]

    text = result.to_text(max_related=2)
    assert text.startswith("## AML.T0102 Generate Malicious Commands  (score: 1.00)")
    assert "Mitigated by (2):" in text
    assert "- ... and 1 more" in text
    assert "[[" not in text

    data = result.to_dict()
    assert data["score"] == 1.0
    assert data["type"] == "technique"
    assert {"id": "AML.S0015", "name": "LAMEHUG"} in data["software"]


def test_all_objects_render_to_json_and_text(keyword_atlas: Atlas) -> None:
    objects = [
        *keyword_atlas.technique_list,
        *keyword_atlas.tactic_list,
        *keyword_atlas.mitigation_list,
        *keyword_atlas.casestudy_list,
        *keyword_atlas.entity_list,
        *keyword_atlas.software_list,
        *(step for cs in keyword_atlas.casestudy_list for step in cs.procedure),
    ]
    for obj in objects:
        json.dumps(obj.to_dict())
        assert obj.to_text().startswith(f"## {obj.id}")


def test_case_study_text_contains_attribution_and_procedure(keyword_atlas: Atlas) -> None:
    text = keyword_atlas.get_case_study_by_id("AML.CS0044").to_text()

    assert "Attributed to: AML.E0018 APT28 [Adversarial Operation]" in text
    assert "Period: 2025-06 (Month)" in text
    assert "- S05 [AI Attack Adaptation] AML.T0102 Generate Malicious Commands -> S06" in text


def test_reverse_relationships(keyword_atlas: Atlas) -> None:
    technique = keyword_atlas.get_technique_by_id("AML.T0102")
    software = keyword_atlas.get_software_by_id("AML.S0015")

    assert {m.id for m in technique.mitigation_list} == {"AML.M0020", "AML.M0022"}
    assert keyword_atlas.get_case_study_by_id("AML.CS0044") in technique.casestudy_list
    assert [e.id for e in software.entity_list] == ["AML.E0018"]
    parent = keyword_atlas.get_technique_by_id("AML.T0051")
    assert keyword_atlas.get_technique_by_id("AML.T0051.000") in parent.subtechnique_list
    assert keyword_atlas.get_technique_by_id("AML.T0051.000").parent is parent


def test_hybrid_search_builds_vector_index_silently(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    embedding_function = _patch_fake_embedding(monkeypatch, tmp_path)

    atlas = Atlas(version="2021.05")
    results = atlas.search_relevant_techniques("evade the model", top_k=3)

    assert atlas.vector_search_enabled
    assert embedding_function.embedded_count > 0
    assert results
    assert all(0 < r.score <= 1 for r in results)
    assert atlas.search_relevant_mitigations("x", top_k=1) == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_vector_index_is_reused_on_next_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_fake_embedding(monkeypatch, tmp_path)
    Atlas(version="2021.05")
    embedding_function = _patch_fake_embedding(monkeypatch, tmp_path)

    Atlas(version="2021.05")

    assert embedding_function.embedded_count == 0


def test_verbose_logs_to_stderr_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_fake_embedding(monkeypatch, tmp_path)

    Atlas(version="2021.05", verbose=True)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "[atlas]" in captured.err
