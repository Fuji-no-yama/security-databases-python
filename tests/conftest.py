from collections.abc import Callable
from typing import TypeVar

import pytest

from _security_databases.settings import settings as environment_settings
from atlas import Atlas
from attack import Attack

T = TypeVar("T")


def build_without_embedding_api(factory: Callable[[], T]) -> T:
    """
    Embedding APIキーを無効にした状態でオブジェクトを作成する。

    単体テストで有料APIを呼んでベクトルDBを作らないようにする。キーを無効にするのは作成中だけで、
    同じセッションで実行される tests/integration には影響しない。
    """
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(environment_settings, "openai_api_key", "")
        mp.setattr(environment_settings, "azure_openai_api_key", "")
        return factory()


@pytest.fixture(scope="session")
def atlas() -> Atlas:
    return build_without_embedding_api(lambda: Atlas(version="2026.10"))


@pytest.fixture(scope="session")
def attack() -> Attack:
    return build_without_embedding_api(lambda: Attack(version="19.1", domain="enterprise"))
