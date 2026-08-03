"""環境変数から共通設定を読み込む。"""

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)


class Settings(BaseSettings):
    """Embedding APIの共通設定。"""

    model_config = SettingsConfigDict(env_file=".env.dev", env_file_encoding="utf-8")

    openai_api_key: str = Field("", alias="OPENAI_API_KEY")
    azure_openai_api_key: str = Field("", alias="AZURE_OPENAI_API_KEY")
    azure_openai_endpoint: str = Field("", alias="AZURE_OPENAI_ENDPOINT")
    azure_openai_api_version: str = Field("", alias="AZURE_OPENAI_API_VERSION")
    azure_openai_embedding_deployment: str = Field("", alias="AZURE_OPENAI_EMBEDDING_DEPLOYMENT")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],  # noqa: ARG003
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """設定値の読み込み優先順位を返す。"""
        return dotenv_settings, init_settings, env_settings, file_secret_settings


load_dotenv(override=True)
settings = Settings()
