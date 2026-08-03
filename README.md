# security-databases-python

MITRE ATLAS と MITRE ATT&CK の Python SDK を、1つの GitHub リポジトリから配布するための統合リポジトリです。

## Install

```bash
pip install git+https://github.com/Fuji-no-yama/security-databases-python
```

```bash
uv add git+https://github.com/Fuji-no-yama/security-databases-python
```

## Packages

このリポジトリは既存の import path を維持します。

```python
from atlas import Atlas
from attack import Attack
```

## Usage

### ATLAS

```python
from atlas import Atlas

atlas = Atlas(version="2026.06")
technique = atlas.get_technique_by_id("AML.T0000")
results = atlas.search_relevant_techniques(
    query="Please search techniques about LLM and RAG",
    top_k=5,
    filter="both",
)
```

### ATT&CK

```python
from attack import Attack

attack = Attack(version="19.1", domain="enterprise")
technique = attack.get_technique_by_id("T1059.001")
results = attack.search_relevant_techniques(
    query="PowerShell execution",
    top_k=5,
    filter="both",
)
```

## API Naming Policy

- Exact lookup: `get_<entity>_by_<key>`
- Vector or semantic search: `search_relevant_<entities>`

旧リポジトリからの主な変更:

| Old | New |
| --- | --- |
| `Atlas.search_tec_from_id` | `Atlas.get_technique_by_id` |
| `Atlas.search_tac_from_id` | `Atlas.get_tactic_by_id` |
| `Atlas.search_mit_from_id` | `Atlas.get_mitigation_by_id` |
| `Atlas.search_cs_from_id` | `Atlas.get_case_study_by_id` |
| `Atlas.search_cs_step_from_id` | `Atlas.get_case_study_step_by_id` |
| `Atlas.search_relevant_technique` | `Atlas.search_relevant_techniques` |
| `Atlas.search_relevant_casestudy` | `Atlas.search_relevant_case_study_steps` |
| `Attack.get_relevant_technique` | `Attack.search_relevant_techniques` |
| `Attack.get_relevant_procedure` | `Attack.search_relevant_procedures` |
