import pytest

from _security_databases.render import clean_text


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("[APT28](https://attack.mitre.org/groups/G0007) is", "APT28 is"),  # マークダウンリンク → 表示名
        ("text[[group-profile]]", "text"),  # 引用マーカー
        ("run <code>procdump -ma lsass.exe</code>", "run `procdump -ma lsass.exe`"),  # <code> → `...`
        ("a<br>b<br/>c", "a\nb\nc"),
        ("<b>bold</b> text", "bold text"),
        ("the <sode>ssh_login</code> module", "the <sode>ssh_login module"),  # 対になっていない </code> は除去
        ("https&#58;&#47;&#47;example &lt;tag&gt;", "https://example <tag>"),  # HTMLエンティティ
        ("the `/proc/<PID>/maps` file", "the `/proc/<PID>/maps` file"),  # プレースホルダーは残す
        ("<atlas-example> # For LLM", "<atlas-example> # For LLM"),  # 攻撃例のタグは残す
        (None, ""),
    ],
)
def test_clean_text(raw: str | None, expected: str) -> None:
    assert clean_text(raw) == expected
