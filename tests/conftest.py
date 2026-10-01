import pytest

from atlas import Atlas
from attack import Attack


@pytest.fixture(scope="session")
def atlas() -> Atlas:
    return Atlas(version="2026.09")


@pytest.fixture(scope="session")
def attack() -> Attack:
    return Attack(version="19.1", domain="enterprise")
