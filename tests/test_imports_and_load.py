from atlas import Atlas
from attack import Attack


def test_atlas_loads_latest_release_without_vector_db() -> None:
    atlas = Atlas()

    assert atlas.technique_list
    assert atlas.tactic_list
    assert atlas.get_available_versions()
    assert atlas.get_technique_by_id(atlas.technique_list[0].id) is atlas.technique_list[0]


def test_attack_loads_enterprise_without_vector_db() -> None:
    attack = Attack(version="19.1", domain="enterprise")

    assert attack.technique_list
    assert attack.tactic_list
    assert attack.get_available_versions()
    assert attack.get_technique_by_id(attack.technique_list[0].id) is attack.technique_list[0]
