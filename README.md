# security-databases-python

MITRE ATLAS と MITRE ATT&CK のデータを Python から扱うためのSDKです。1つの配布物から、独立した `atlas` と `attack` の2パッケージを利用できます。

## 必要環境

- Python 3.10以上
- セマンティック検索を使う場合のみOpenAIまたはAzure OpenAIの接続情報

## インストール

リリース版をインストールする場合:

```bash
pip install "security-databases-python @ git+https://github.com/Fuji-no-yama/security-databases-python@v1.1.1"
```

```bash
uv add git+https://github.com/Fuji-no-yama/security-databases-python --tag v1.1.1
```

開発版を利用する場合:

```bash
uv add git+https://github.com/Fuji-no-yama/security-databases-python --branch dev
```

既存SDKと同じimport pathを維持しています。

```python
from atlas import Atlas
from attack import Attack
```

## Embedding provider

セマンティック検索ではOpenAIとAzure OpenAIを選択できます。デフォルトは既存互換の `openai` です。providerはATLASとATT&CKの初期化引数 `embedding_provider` で明示し、認証情報は環境変数またはプロジェクトルートの `.env.dev` から読み込みます。

### OpenAI

```dotenv
OPENAI_API_KEY=your-openai-api-key
```

```python
from atlas import Atlas
from attack import Attack

atlas = Atlas(
    embedding_provider="openai",
    emb_model="text-embedding-3-small",
)

attack = Attack(
    embedding_provider="openai",
    emb_model="text-embedding-3-small",
)
```

`embedding_provider`は省略できるため、従来の `Atlas()` と `Attack()` も `OPENAI_API_KEY` が設定されていればOpenAIを使用します。APIキーがない場合、通常のデータ取得は利用できますが、セマンティック検索は無効になります。

### Azure OpenAI

Azure OpenAIでは、Embeddingモデルをデプロイしたリソースの情報を設定します。

```dotenv
AZURE_OPENAI_API_KEY=your-azure-openai-api-key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_API_VERSION=your-api-version
AZURE_OPENAI_EMBEDDING_DEPLOYMENT=your-embedding-deployment
```

```python
from atlas import Atlas
from attack import Attack

atlas = Atlas(
    embedding_provider="azure_openai",
)

attack = Attack(
    embedding_provider="azure_openai",
)
```

Azure OpenAIでは `AZURE_OPENAI_EMBEDDING_DEPLOYMENT` がAPI呼び出し時のモデル識別子になり、`emb_model`は使用しません。必須環境変数が不足している場合は、オブジェクト初期化時に `ValueError` を送出します。OpenAI用とAzure OpenAI用の環境変数が両方存在していても、`embedding_provider`で指定したproviderだけを使用します。

### ベクトルDB

初回実行時はChroma DBを自動作成し、進捗を表示します。再作成する場合は `initialize_vector=True` を指定します。

DBはデータバージョンに加え、provider・モデルまたはAzure deployment・endpointごとに分離されます。ディレクトリ名末尾には設定を識別するハッシュが付きます。

```text
atlas/releases/<release>/chroma/openai-<model>-<hash>/
atlas/releases/<release>/chroma/azure_openai-<deployment>-<hash>/

attack/releases/<version>/<domain>/chroma/openai-<model>-<hash>/
attack/releases/<version>/<domain>/chroma/azure_openai-<deployment>-<hash>/
```

この分離により、異なるモデルやproviderで作成したベクトルを誤って検索に使うことを防ぎます。旧バージョンが作成した `chroma` 直下のDBは再利用されず、認証情報設定後の初回オブジェクト初期化時に新しい保存先へ再構築されます。

## MITRE ATLAS

### 初期化とバージョン

`version`を省略すると、[`atlas/data/manifest.yaml`](atlas/data/manifest.yaml) に記載された最新リリースを読み込みます。推奨する指定方法はATLASのリリース識別子です。旧format-versionもmanifestを介して対応するv6データへ解決されます。

```python
from atlas import Atlas

atlas = Atlas(version="2026.09")
# atlas = Atlas()                 # 最新リリース
# atlas = Atlas(version="5.6.0") # 旧format-version

print(atlas.release)
print(atlas.get_available_versions())
print(atlas.get_available_legacy_versions())
```

主要な一覧は次の属性から取得できます。

```python
atlas.tactic_list
atlas.technique_list
atlas.mitigation_list
atlas.casestudy_list
atlas.relationships
```

### IDによる取得

```python
technique = atlas.get_technique_by_id("AML.T0000")
tactic = atlas.get_tactic_by_id("AML.TA0000")
mitigation = atlas.get_mitigation_by_id("AML.M0000")
case_study = atlas.get_case_study_by_id("AML.CS0000")
case_study_step = atlas.get_case_study_step_by_id("AML.CS0000.S00")

print(technique.name)
print([item.id for item in tactic.technique_list])
print([item.id for item in mitigation.technique_list])
print([step.technique.id for step in case_study.procedure])
print(case_study_step.description)
```

IDが存在しない場合、各取得メソッドは `ValueError` を送出します。

### Relationships

v6データのrelationshipは `get_relationships()` で起点、対象、種別を絞り込めます。種別は `achieves`、`specializes`、`mitigates`、`employs`、`sequences` です。

```python
relationships = atlas.get_relationships(
    target_id="AML.T0000",
    type="mitigates",
)

for relationship in relationships:
    print(relationship.source_id, relationship.target_id)
```

### セマンティック検索

```python
from atlas import Atlas

atlas = Atlas(
    version="2026.09",
    emb_model="text-embedding-3-small",
    embedding_provider="openai",  # または "azure_openai"
)

techniques = atlas.search_relevant_techniques(
    query="LLMとRAGに関連する攻撃手法",
    top_k=5,
    filter="both",  # parent / child / both
)

steps = atlas.search_relevant_case_study_steps(
    query="RAGを利用したシステムへの攻撃",
    top_k=3,
)
```

## MITRE ATT&CK

### 初期化とバージョン

ATT&CKではデータ構造に合わせて `enterprise`、`mobile`、`ics` のいずれかのdomainを指定します。`version`を省略すると、[`attack/data/manifest.yaml`](attack/data/manifest.yaml) に記載された最新バージョンを使用します。

```python
from attack import Attack

attack = Attack(version="19.1", domain="enterprise")
# attack = Attack(domain="mobile")
# attack = Attack(domain="ics")

print(attack.version)
print(attack.get_available_versions())
```

主要な一覧は次の属性から取得できます。

```python
attack.tactic_list
attack.technique_list
attack.mitigation_list
attack.campaign_list
attack.group_list
attack.software_list
attack.external_reference_list
```

### エンティティの取得

```python
technique = attack.get_technique_by_id("T1059.001")
tactic = attack.get_tactic_by_id("TA0001")
tactic_by_name = attack.get_tactic_by_name("Initial Access")
mitigation = attack.get_mitigation_by_id("M1049")
campaign = attack.get_campaign_by_id("C0001")
group = attack.get_group_by_id("G0001")
software = attack.get_software_by_id("S0001")

procedures = attack.get_procedure_by_technique_id("T1059.001")
concrete_mitigations = attack.get_concrete_mitigation_by_technique_id("T1059.001")

print(technique.name)
print(tactic.id, tactic_by_name.id)
print([procedure.parent_name for procedure in procedures])
print([item.abstract_mitigation_name for item in concrete_mitigations])
```

ATT&CKのdescription中の引用は番号へ整形されています。参考資料を含む文章が必要な場合は、対応するエンティティの `get_description_include_references()` を使用します。

```python
print(group.get_description_include_references())
```

### セマンティック検索

先にOpenAIまたはAzure OpenAIの環境変数を設定します。

```python
from attack import Attack

attack = Attack(
    version="19.1",
    domain="enterprise",
    emb_model="text-embedding-3-small",
    embedding_provider="openai",  # または "azure_openai"
)

techniques = attack.search_relevant_techniques(
    query="PowerShellを利用したコマンド実行",
    top_k=5,
    filter="both",  # parent / child / both
)

procedures = attack.search_relevant_procedures(
    query="悪意のある添付ファイルを利用したフィッシング",
    top_k=5,
    filter="all",  # campaign / group / software / all
)
```

## API命名規則と移行

- IDや名前による完全一致取得: `get_<entity>_by_<key>`
- ベクトルによる関連検索: `search_relevant_<entities>`

| 旧API | 新API |
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

## 開発

```bash
uv sync --all-groups
uv run ruff check
uv run ty check
uv run pytest -m "not integration" -v
```

Embedding APIを利用するintegration testは、必要な環境変数を設定して個別に実行します。

```bash
uv run pytest -m integration -v
```

## ライセンスとデータ

コードのライセンスは [LICENSE](LICENSE)、同梱するMITRE ATLASおよびMITRE ATT&CKデータの帰属情報は [NOTICE](NOTICE) を参照してください。
