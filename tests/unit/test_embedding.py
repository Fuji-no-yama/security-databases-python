import pytest

from _security_databases.embedding import create_embedding_function, resolve_embedding_configuration
from _security_databases.settings import Settings
from _security_databases.settings import settings as environment_settings
from atlas import Atlas
from attack import Attack


def _settings(
    *,
    openai_api_key: str = "",
    azure_openai_api_key: str = "",
    azure_openai_endpoint: str = "",
    azure_openai_api_version: str = "",
    azure_openai_embedding_deployment: str = "",
) -> Settings:
    return Settings.model_construct(
        openai_api_key=openai_api_key,
        azure_openai_api_key=azure_openai_api_key,
        azure_openai_endpoint=azure_openai_endpoint,
        azure_openai_api_version=azure_openai_api_version,
        azure_openai_embedding_deployment=azure_openai_embedding_deployment,
    )


def test_openai_configuration_uses_model_specific_cache() -> None:
    settings = _settings(openai_api_key="openai-key")

    small = resolve_embedding_configuration("openai", "text-embedding-3-small", configured_settings=settings)
    large = resolve_embedding_configuration("openai", "text-embedding-3-large", configured_settings=settings)

    assert small is not None
    assert large is not None
    assert small.model_name == "text-embedding-3-small"
    assert small.cache_key != large.cache_key


def test_openai_without_api_key_disables_vector_search() -> None:
    configuration = resolve_embedding_configuration("openai", "text-embedding-3-small", configured_settings=_settings())

    assert configuration is None


def test_azure_configuration_uses_deployment_and_endpoint() -> None:
    settings = _settings(
        azure_openai_api_key="azure-key",
        azure_openai_endpoint="https://example.openai.azure.com/",
        azure_openai_api_version="2024-02-01",
        azure_openai_embedding_deployment="embedding-large",
    )

    configuration = resolve_embedding_configuration("azure_openai", "text-embedding-3-large", configured_settings=settings)

    assert configuration is not None
    assert configuration.model_name == "embedding-large"
    assert configuration.deployment_id == "embedding-large"
    assert configuration.api_base == "https://example.openai.azure.com/"
    assert configuration.api_version == "2024-02-01"
    assert configuration.cache_key.startswith("azure_openai-embedding-large-")

    with pytest.warns(DeprecationWarning, match="Direct api_key configuration"):
        embedding_function = create_embedding_function(configuration)
    assert embedding_function.api_type == "azure"
    assert embedding_function.deployment_id == "embedding-large"


def test_azure_configuration_requires_all_environment_variables() -> None:
    with pytest.raises(ValueError, match="AZURE_OPENAI_ENDPOINT"):
        resolve_embedding_configuration(
            "azure_openai",
            "text-embedding-3-small",
            configured_settings=_settings(azure_openai_api_key="azure-key"),
        )


@pytest.mark.parametrize("database_class", [Atlas, Attack])
def test_database_rejects_incomplete_azure_configuration(
    database_class: type[Atlas] | type[Attack],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(environment_settings, "azure_openai_api_key", "azure-key")
    monkeypatch.setattr(environment_settings, "azure_openai_endpoint", "")
    monkeypatch.setattr(environment_settings, "azure_openai_api_version", "")
    monkeypatch.setattr(environment_settings, "azure_openai_embedding_deployment", "")

    with pytest.raises(ValueError, match="AZURE_OPENAI_ENDPOINT"):
        database_class(embedding_provider="azure_openai")
