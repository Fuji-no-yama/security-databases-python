import pytest

from atlas import Atlas
from atlas.config import settings as atlas_settings
from attack import Attack
from attack.config import settings as attack_settings

pytestmark = pytest.mark.integration


def test_atlas_vector_search() -> None:
    if not atlas_settings.openai_api_key:
        pytest.skip("OPENAI_API_KEY is not configured")

    atlas = Atlas(version="2026.06", emb_model="text-embedding-3-small")
    assert atlas.search_relevant_techniques("LLM and RAG", top_k=1)
    assert atlas.search_relevant_case_study_steps("RAG attack", top_k=1)


def test_attack_vector_search() -> None:
    if not attack_settings.openai_api_key:
        pytest.skip("OPENAI_API_KEY is not configured")

    attack = Attack(version="19.1", domain="enterprise", emb_model="text-embedding-3-small")
    assert attack.search_relevant_techniques("PowerShell execution", top_k=1)
    assert attack.search_relevant_procedures("malicious attachment", top_k=1)
