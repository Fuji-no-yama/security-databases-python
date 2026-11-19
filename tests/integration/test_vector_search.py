import pytest

from atlas import Atlas
from atlas.config import settings as atlas_settings
from attack import Attack
from attack.config import settings as attack_settings

pytestmark = pytest.mark.integration


def test_atlas_vector_search() -> None:
    if not atlas_settings.openai_api_key:
        pytest.skip("OPENAI_API_KEY is not configured")

    atlas = Atlas(version="2026.10", emb_model="text-embedding-3-small")
    assert atlas.vector_search_enabled
    assert atlas.search_relevant_techniques("LLM and RAG", top_k=1)[0].score > 0
    assert atlas.search_relevant_mitigations("guardrails for generative AI", top_k=1)
    assert atlas.search_relevant_case_studies("prompt injection incident", top_k=1)
    assert atlas.search_relevant_case_study_steps("RAG attack", top_k=1)


@pytest.mark.parametrize(
    ("query", "kind", "expected_id"),
    [
        # キーワードスコアを混ぜていた頃に順位が下がっていた事例。ベクトル検索のみなら1位になる
        ("malware that uses an LLM to generate commands", "technique", "AML.T0102"),
        ("attack by Russian state-sponsored group", "case_study", "AML.CS0044"),
    ],
)
def test_atlas_vector_search_ranking(query: str, kind: str, expected_id: str) -> None:
    if not atlas_settings.openai_api_key:
        pytest.skip("OPENAI_API_KEY is not configured")

    atlas = Atlas(version="2026.10", emb_model="text-embedding-3-small")
    search = atlas.search_relevant_techniques if kind == "technique" else atlas.search_relevant_case_studies
    assert search(query, top_k=1)[0].item.id == expected_id


def test_attack_vector_search() -> None:
    if not attack_settings.openai_api_key:
        pytest.skip("OPENAI_API_KEY is not configured")

    attack = Attack(version="20.1", domain="enterprise", emb_model="text-embedding-3-small")
    assert attack.vector_search_enabled
    assert attack.search_relevant_techniques("PowerShell execution", top_k=1)[0].score > 0
    assert attack.search_relevant_procedures("malicious attachment", top_k=1)
    assert attack.search_relevant_mitigations("restrict administrator privileges", top_k=1)
    assert attack.search_relevant_groups("Russian state-sponsored espionage group", top_k=1)
    assert attack.search_relevant_software("remote access trojan", top_k=1)
    assert attack.search_relevant_campaigns("supply chain compromise of IT management software", top_k=1)


def test_atlas_vector_search_with_azure_openai() -> None:
    if not all(
        (
            atlas_settings.azure_openai_api_key,
            atlas_settings.azure_openai_endpoint,
            atlas_settings.azure_openai_api_version,
            atlas_settings.azure_openai_embedding_deployment,
        ),
    ):
        pytest.skip("Azure OpenAI is not configured")

    atlas = Atlas(version="2026.10", embedding_provider="azure_openai")
    assert atlas.vector_search_enabled
    assert atlas.search_relevant_techniques("LLM and RAG", top_k=1)[0].score > 0
    assert atlas.search_relevant_mitigations("guardrails for generative AI", top_k=1)
    assert atlas.search_relevant_case_studies("prompt injection incident", top_k=1)
    assert atlas.search_relevant_case_study_steps("RAG attack", top_k=1)


def test_attack_vector_search_with_azure_openai() -> None:
    if not all(
        (
            attack_settings.azure_openai_api_key,
            attack_settings.azure_openai_endpoint,
            attack_settings.azure_openai_api_version,
            attack_settings.azure_openai_embedding_deployment,
        ),
    ):
        pytest.skip("Azure OpenAI is not configured")

    attack = Attack(version="20.1", domain="enterprise", embedding_provider="azure_openai")
    assert attack.vector_search_enabled
    assert attack.search_relevant_techniques("PowerShell execution", top_k=1)[0].score > 0
    assert attack.search_relevant_procedures("malicious attachment", top_k=1)


@pytest.mark.parametrize(
    ("query", "kind", "expected_id"),
    [
        ("obtaining credentials from LSASS process memory", "technique", "T1003.001"),
        ("Russian military intelligence GRU unit", "group", "G0007"),
        ("compromise of SolarWinds Orion software updates", "campaign", "C0024"),
    ],
)
def test_attack_vector_search_ranking(query: str, kind: str, expected_id: str) -> None:
    if not attack_settings.openai_api_key:
        pytest.skip("OPENAI_API_KEY is not configured")

    attack = Attack(version="20.1", domain="enterprise", emb_model="text-embedding-3-small")
    search = {
        "technique": attack.search_relevant_techniques,
        "group": attack.search_relevant_groups,
        "campaign": attack.search_relevant_campaigns,
    }[kind]
    assert search(query, top_k=1)[0].item.id == expected_id
