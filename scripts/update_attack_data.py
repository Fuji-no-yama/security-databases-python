"""MITRE ATT&CKの公式STIX 2.1データを取得し、gzip圧縮してパッケージに配置するスクリプト。

使い方:
    uv run python scripts/update_attack_data.py 20.1 20.0 ...

取得元: https://github.com/mitre-attack/attack-stix-data
- attack/data/v{version}/{domain}-attack-{version}.json.gz に公式ファイルをそのままgzip圧縮して保存する
- attack/data/manifest.yaml の versions と latest を更新する(最新バージョンが latest になる)
"""

import argparse
import gzip
import hashlib
import ssl
import sys
import urllib.request
from pathlib import Path

import yaml

try:
    import certifi

    # macOS の python.org 版Pythonなどでシステムの証明書が使えない環境向け
    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CONTEXT = ssl.create_default_context()

BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
DOMAINS = ("enterprise", "mobile", "ics")
DATA_DIR = Path(__file__).resolve().parents[1] / "attack" / "data"


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def download(version: str, domain: str) -> Path:
    """1ドメイン・1バージョン分のSTIXバンドルを取得しgzip圧縮して保存する。"""
    url = f"{BASE_URL}/{domain}-attack/{domain}-attack-{version}.json"
    with urllib.request.urlopen(url, timeout=120, context=_SSL_CONTEXT) as response:  # noqa: S310
        body: bytes = response.read()
    if not body.lstrip().startswith(b"{"):
        err = f"JSONではないデータを受信しました: {url}"
        raise ValueError(err)
    out_dir = DATA_DIR / f"v{version}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{domain}-attack-{version}.json.gz"
    # mtime=0 にして同じ入力から常に同じgzipファイルが生成されるようにする
    out_path.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    print(f"{out_path.relative_to(DATA_DIR.parent.parent)}  sha256(json)={hashlib.sha256(body).hexdigest()[:16]}")
    return out_path


def update_manifest(versions: list[str]) -> None:
    """manifest.yaml に取得したバージョンを追加し、latest を最新バージョンにする。"""
    manifest_path = DATA_DIR / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text()) if manifest_path.exists() else {}
    known = {str(entry["version"]) for entry in manifest.get("versions", [])}
    all_versions = sorted(known | set(versions), key=_version_key, reverse=True)
    manifest = {
        "latest": all_versions[0],
        "domains": list(DOMAINS),
        "versions": [{"version": v, "path": f"v{v}"} for v in all_versions],
    }
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True))


def main() -> int:  # noqa: D103
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("versions", nargs="+", help="取得するATT&CKバージョン (例: 20.1)")
    args = parser.parse_args()
    for version in args.versions:
        for domain in DOMAINS:
            download(version, domain)
    update_manifest(args.versions)
    return 0


if __name__ == "__main__":
    sys.exit(main())
