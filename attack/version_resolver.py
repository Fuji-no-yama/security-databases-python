"""ATT&CKデータのバージョンとドメインを解決するモジュール。"""

from importlib.resources import files
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from importlib.abc import Traversable


class ManifestEntry:
    """
    manifest.yamlの1バージョンエントリを表すデータクラス。

    Args:
        version (str): ATT&CKのバージョン文字列
        path (str): attack.data配下のデータディレクトリ
    """

    def __init__(self, version: str, path: str) -> None:
        self.version: str = version
        self.path: str = path


def _load_manifest_raw() -> dict[str, Any]:
    manifest_file: Traversable = files("attack.data").joinpath("manifest.yaml")
    with manifest_file.open() as f:
        raw: dict[str, Any] = yaml.safe_load(f)
    return raw


def load_manifest() -> list[ManifestEntry]:
    """
    manifest.yamlをロードしバージョンエントリのリストを返す。

    Returns:
        list[ManifestEntry]: manifest.yamlに記載されたバージョンエントリ一覧
    """
    raw = _load_manifest_raw()
    return [ManifestEntry(version=str(item["version"]), path=str(item["path"])) for item in raw.get("versions", [])]


def list_versions() -> list[str]:
    """
    利用可能なATT&CKバージョン一覧を返す。

    Returns:
        list[str]: 昇順ソートされたバージョン文字列のリスト
    """
    return sorted(entry.version for entry in load_manifest())


def list_domains() -> list[str]:
    """
    利用可能なATT&CKドメイン一覧を返す。

    Returns:
        list[str]: manifest.yamlに記載されたドメイン一覧
    """
    raw = _load_manifest_raw()
    return [str(domain) for domain in raw.get("domains", [])]


def latest_version() -> str:
    """
    manifest.yamlに記載された最新ATT&CKバージョンを返す。

    Returns:
        str: 最新バージョン文字列
    """
    raw = _load_manifest_raw()
    latest = raw.get("latest")
    if latest is None:
        err = "manifest.yaml に latest がありません。"
        raise ValueError(err)
    return str(latest)


def resolve(version: str) -> tuple[str, str]:
    """
    ユーザ指定のバージョン文字列を(version, データディレクトリパス)に解決する。

    Args:
        version (str): 解決対象のバージョン文字列

    Returns:
        tuple[str, str]: (バージョン文字列, attack.data配下のデータディレクトリ)

    Raises:
        ValueError: 指定バージョンがmanifest.yamlに存在しない場合
    """
    key = version.lstrip("v")
    for entry in load_manifest():
        if entry.version == key:
            return entry.version, entry.path
    available = list_versions()
    err = f"version must be one of {available}. '{version}' is given."
    raise ValueError(err)
