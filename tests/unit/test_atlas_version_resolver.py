import pytest

from atlas import version_resolver


def test_v6_minor_format_versions_are_treated_as_v6() -> None:
    entries = version_resolver.load_manifest()
    v6_format_versions = {e.v6_format_version for e in entries if e.v6_format_version is not None}

    assert {"6.0.0", "6.1.0"} <= v6_format_versions
    assert not v6_format_versions & set(version_resolver.list_legacy_versions())


def test_resolves_6_1_0_release() -> None:
    release, path = version_resolver.resolve("2026.10")

    assert release == "2026.10"
    assert path == "v6/ATLAS-2026.10.yaml"
    assert "2026.10" in version_resolver.list_releases()


def test_latest_release_is_first_v6_manifest_entry() -> None:
    first_v6 = next(e for e in version_resolver.load_manifest() if e.v6_path is not None)

    assert version_resolver.latest_release() == first_v6.release


def test_legacy_version_falls_back_to_v6_file() -> None:
    assert version_resolver.resolve("5.6.0") == ("2026.04", "v6/ATLAS-2026.04.yaml")


def test_rejects_unknown_version() -> None:
    with pytest.raises(ValueError, match="version must be one of"):
        version_resolver.resolve("6.1.0")
