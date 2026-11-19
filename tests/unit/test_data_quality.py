"""
同梱データの中身(名前・説明文)と、テキスト出力の品質を全リリース・全バージョンで検査する。

上流データの更新や読み込み処理の変更で、空の値・文字化け・整形漏れが混入した場合に検出する。
上流データ自体に正当な空値などが含まれるようになった場合は、理由を添えて個別に除外すること。
"""

import re
from collections.abc import Iterator
from functools import cache
from typing import Any

import pytest

from atlas import Atlas
from atlas import version_resolver as atlas_versions
from attack import Attack
from attack import version_resolver as attack_versions
from tests.conftest import build_without_embedding_api

# 文字化けの典型パターン: 置換文字、UTF-8をLatin-1として解釈した痕跡 (Ã©, â€™, Â など)、制御文字 (改行・タブ以外)
MOJIBAKE = re.compile(r"�|Ã[\x80-\xbf]|â€|Â[\xa0-\xbf]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# to_text() で除去・変換されているべき記法
LEFTOVER_MARKUP = re.compile(r"\(Citation: |\[\[[^\]]+\]\]|</?code>|<br\s*/?>|</?b>|&(?:lt|gt|amp|quot|#\d+);", re.IGNORECASE)

ATTACK_DOMAINS = ("enterprise", "mobile", "ics")


@cache
def _atlas(release: str) -> Atlas:
    return build_without_embedding_api(lambda: Atlas(version=release))


@cache
def _attack(version: str, domain: str) -> Attack:
    return build_without_embedding_api(lambda: Attack(version=version, domain=domain))


def _atlas_fields(atlas: Atlas) -> Iterator[tuple[Any, str, str]]:
    """(オブジェクト, 項目名, 値) を列挙する。"""
    for obj in [*atlas.technique_list, *atlas.tactic_list, *atlas.mitigation_list, *atlas.entity_list, *atlas.software_list]:
        yield obj, "name", obj.name
        yield obj, "description", obj.description
    for cs in atlas.casestudy_list:
        yield cs, "name", cs.name
        yield cs, "summary", cs.summary
        for step in cs.procedure:
            yield step, "description", step.description


def _attack_fields(attack: Attack) -> Iterator[tuple[Any, str, str]]:
    for obj in [
        *attack.technique_list,
        *attack.tactic_list,
        *attack.mitigation_list,
        *attack.group_list,
        *attack.software_list,
        *attack.campaign_list,
    ]:
        yield obj, "name", obj.name
        yield obj, "description", obj.description
    for parent in [*attack.campaign_list, *attack.group_list, *attack.software_list]:
        for procedure in parent.procedure_list:
            yield procedure, "description", procedure.description
    for mitigation in attack.mitigation_list:
        for concrete in mitigation.concrete_mitigation_list:
            yield concrete, "description", concrete.description


def _atlas_renderables(atlas: Atlas) -> list[Any]:
    steps = [step for cs in atlas.casestudy_list for step in cs.procedure]
    return [
        *atlas.technique_list,
        *atlas.tactic_list,
        *atlas.mitigation_list,
        *atlas.casestudy_list,
        *atlas.entity_list,
        *atlas.software_list,
        *steps,
    ]


def _attack_renderables(attack: Attack) -> list[Any]:
    procedures = [p for parent in [*attack.campaign_list, *attack.group_list, *attack.software_list] for p in parent.procedure_list]
    return [
        *attack.technique_list,
        *attack.tactic_list,
        *attack.mitigation_list,
        *attack.group_list,
        *attack.software_list,
        *attack.campaign_list,
        *procedures,
    ]


def _field_problems(fields: Iterator[tuple[Any, str, str]]) -> list[str]:
    problems = []
    for obj, field, value in fields:
        label = f"{getattr(obj, 'id', obj)}.{field}"
        if not value or not value.strip():
            problems.append(f"{label}: empty")
        elif match := MOJIBAKE.search(value):
            problems.append(f"{label}: mojibake-like {value[max(0, match.start() - 20) : match.end() + 20]!r}")
    return problems


def _text_problems(objects: list[Any]) -> list[str]:
    problems = []
    for obj in objects:
        text = obj.to_text()
        body = text.split("\n", 2)[-1].strip()
        if not body:
            problems.append(f"{obj.id}: empty text body")
        for pattern, kind in ((MOJIBAKE, "mojibake-like"), (LEFTOVER_MARKUP, "leftover markup")):
            if match := pattern.search(text):
                problems.append(f"{obj.id}: {kind} {text[max(0, match.start() - 20) : match.end() + 20]!r}")
    return problems


@pytest.mark.parametrize("release", atlas_versions.list_releases())
def test_atlas_names_and_descriptions(release: str) -> None:
    problems = _field_problems(_atlas_fields(_atlas(release)))

    assert not problems, "\n".join(problems[:20])


@pytest.mark.parametrize("release", atlas_versions.list_releases())
def test_atlas_text_output(release: str) -> None:
    problems = _text_problems(_atlas_renderables(_atlas(release)))

    assert not problems, "\n".join(problems[:20])


@pytest.mark.parametrize("version", attack_versions.list_versions())
@pytest.mark.parametrize("domain", ATTACK_DOMAINS)
def test_attack_names_and_descriptions(version: str, domain: str) -> None:
    problems = _field_problems(_attack_fields(_attack(version, domain)))

    assert not problems, "\n".join(problems[:20])


@pytest.mark.parametrize("version", attack_versions.list_versions())
@pytest.mark.parametrize("domain", ATTACK_DOMAINS)
def test_attack_text_output(version: str, domain: str) -> None:
    problems = _text_problems(_attack_renderables(_attack(version, domain)))

    assert not problems, "\n".join(problems[:20])


def test_text_keeps_placeholders_and_attack_examples() -> None:
    """書式タグ以外の "<...>" はプレースホルダーや攻撃例そのものなので、テキスト出力でも残す。"""
    attack = _attack("20.1", "enterprise")
    atlas = _atlas("2026.10")

    lsass = attack.get_technique_by_id("T1003.001").to_text()
    assert "`procdump -ma lsass.exe lsass_dump`" in lsass  # <code> → `...`
    proc_maps = attack.get_technique_by_id("T1003.007").to_text()
    assert "/proc/<PID>/maps" in proc_maps
    assert any("<atlas-" in cs.to_text() for cs in atlas.casestudy_list)
