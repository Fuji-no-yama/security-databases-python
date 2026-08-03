"""Embedding providerごとのChroma設定を共通化する。"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Literal

from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction

from _security_databases.settings import Settings, settings

EmbeddingProvider = Literal["openai", "azure_openai"]
EmbeddingModel = Literal["text-embedding-3-small", "text-embedding-3-large"]


@dataclass(frozen=True)
class EmbeddingConfiguration:
    """Embedding functionの解決済み設定。"""

    provider: EmbeddingProvider
    model_name: str
    api_key: str = field(repr=False)
    cache_key: str
    api_base: str | None = None
    api_version: str | None = None
    deployment_id: str | None = None


def _cache_key(provider: EmbeddingProvider, model: str, endpoint: str = "", api_version: str = "") -> str:
    identity = "|".join((provider, model, endpoint.rstrip("/"), api_version))
    digest = hashlib.sha256(identity.encode()).hexdigest()[:12]
    label = re.sub(r"[^a-zA-Z0-9._-]+", "-", model).strip("-") or "embedding"
    return f"{provider}-{label}-{digest}"


def resolve_embedding_configuration(
    provider: EmbeddingProvider,
    model: EmbeddingModel,
    *,
    configured_settings: Settings = settings,
) -> EmbeddingConfiguration | None:
    """providerと環境設定からEmbedding設定を解決する。

    Args:
        provider (EmbeddingProvider): 利用するEmbedding provider
        model (EmbeddingModel): OpenAIのEmbeddingモデル
        configured_settings (Settings): 環境変数から読み込んだ設定

    Returns:
        EmbeddingConfiguration | None: 解決済み設定。OpenAI APIキー未設定時はNone

    Raises:
        ValueError: providerが不正、またはAzure OpenAIの必須設定が不足している場合
    """
    if provider not in ("openai", "azure_openai"):
        err_msg = f"embedding_providerは'openai'または'azure_openai'を指定してください: {provider}"
        raise ValueError(err_msg)

    if provider == "openai":
        if not configured_settings.openai_api_key:
            return None
        return EmbeddingConfiguration(
            provider=provider,
            model_name=model,
            api_key=configured_settings.openai_api_key,
            cache_key=_cache_key(provider, model),
        )

    required_values = {
        "AZURE_OPENAI_API_KEY": configured_settings.azure_openai_api_key,
        "AZURE_OPENAI_ENDPOINT": configured_settings.azure_openai_endpoint,
        "AZURE_OPENAI_API_VERSION": configured_settings.azure_openai_api_version,
        "AZURE_OPENAI_EMBEDDING_DEPLOYMENT": configured_settings.azure_openai_embedding_deployment,
    }
    missing = [name for name, value in required_values.items() if not value]
    if missing:
        err_msg = f"Azure OpenAIの必須環境変数が設定されていません: {', '.join(missing)}"
        raise ValueError(err_msg)

    deployment = configured_settings.azure_openai_embedding_deployment
    endpoint = configured_settings.azure_openai_endpoint
    api_version = configured_settings.azure_openai_api_version
    return EmbeddingConfiguration(
        provider=provider,
        model_name=deployment,
        api_key=configured_settings.azure_openai_api_key,
        api_base=endpoint,
        api_version=api_version,
        deployment_id=deployment,
        cache_key=_cache_key(provider, deployment, endpoint, api_version),
    )


def create_embedding_function(configuration: EmbeddingConfiguration) -> OpenAIEmbeddingFunction:
    """解決済み設定からChromaのEmbedding functionを作成する。

    Args:
        configuration (EmbeddingConfiguration): 解決済みEmbedding設定

    Returns:
        OpenAIEmbeddingFunction: OpenAIまたはAzure OpenAI用のEmbedding function
    """
    return OpenAIEmbeddingFunction(
        api_key=configuration.api_key,
        model_name=configuration.model_name,
        api_base=configuration.api_base,
        api_type="azure" if configuration.provider == "azure_openai" else None,
        api_version=configuration.api_version,
        deployment_id=configuration.deployment_id,
    )
