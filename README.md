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

開発版(mainブランチの最新)を利用する場合:

```bash
uv add git+https://github.com/Fuji-no-yama/security-databases-python --branch main
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

`embedding_provider`は省略できるため、従来の `Atlas()` と `Attack()` も `OPENAI_API_KEY` が設定されていればOpenAIを使用します。APIキーがない場合も通常のデータ取得は利用できます。検索は、ATLASではキーワード検索のみで動作し、ATT&CKでは無効になります。

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

初回実行時はChroma DBを自動作成します。

- **ATLAS**: 各コレクションに作成時のインデックス形式とデータのハッシュを記録し、ライブラリの更新でベクトル化の方法やデータが変わった場合は、次回の初期化時に該当するコレクションだけを自動で再構築します。通常は何も出力しません。進捗を表示したい場合は `verbose=True` を指定します(出力先は標準エラー出力)。強制的に再構築する場合は `initialize_vector=True` を指定します。
- **ATT&CK**: 初回作成時に進捗を表示します。再作成する場合は `initialize_vector=True` を指定します。

DBはデータバージョンに加え、provider・モデルまたはAzure deployment・endpointごとに分離されます。ディレクトリ名末尾には設定を識別するハッシュが付きます。

```text
atlas/releases/<release>/chroma/openai-<model>-<hash>/
atlas/releases/<release>/chroma/azure_openai-<deployment>-<hash>/

attack/releases/<version>/<domain>/chroma-stix/openai-<model>-<hash>/
attack/releases/<version>/<domain>/chroma-stix/azure_openai-<deployment>-<hash>/
```

この分離により、異なるモデルやproviderで作成したベクトルを誤って検索に使うことを防ぎます。旧バージョンが作成した `chroma` 直下のDBは再利用されず、認証情報設定後の初回オブジェクト初期化時に新しい保存先へ再構築されます。

## MITRE ATLAS

### 初期化とバージョン

`version`を省略すると、[`atlas/data/manifest.yaml`](atlas/data/manifest.yaml) に記載された最新リリースを読み込みます。推奨する指定方法はATLASのリリース識別子です。旧format-versionもmanifestを介して対応するv6データへ解決されます。

```python
from atlas import Atlas

atlas = Atlas(version="2026.10")
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
atlas.entity_list      # 2026.10以降
atlas.software_list    # 2026.10以降
atlas.relationships
```

ATLASは標準では標準出力・標準エラー出力に何も表示しません。ベクトルDB構築などの進捗を確認したい場合は `Atlas(verbose=True)` を指定します。表示は標準エラー出力に行われるため、標準入出力で通信するMCPサーバーなどに組み込んでも通信を妨げません。ログはロガー名 `atlas` で個別に制御することもできます。

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

### エンティティとソフトウェア (2026.10以降)

format-version 6.1.0 (リリース2026.10) から、活動主体を表すエンティティ (`AML.E####`) と、ツール・マルウェアを表すソフトウェア (`AML.S####`) が追加されました。

```python
atlas = Atlas(version="2026.10")

case_study = atlas.get_case_study_by_id("AML.CS0044")
for attribution in case_study.attributions:          # 帰属先と活動目的
    print(attribution.entity.name, attribution.activity_purpose)  # APT28 Adversarial Operation
print([e.name for e in case_study.reported_by])        # 報告者エンティティ
print([s.name for s in case_study.software_list])      # 使用されたソフトウェア
print(case_study.start_date, case_study.start_date_granularity, case_study.end_date)

entity = atlas.get_entity_by_id("AML.E0018")
print(entity.entity_type, entity.attack_reference.id)  # Activity Cluster G0007
print([s.name for s in entity.software_list])          # LAMEHUG

software = atlas.get_software_by_id("AML.S0015")
print(software.aliases)                                # ['PROMPTSTEAL']
print([t.id for t in software.technique_list])         # 実装するテクニック

technique = atlas.get_technique_by_id("AML.T0102")
print([s.name for s in technique.software_list])       # このテクニックを実装するソフトウェア
```

ライブラリはデータに存在する値のみを返し、リリース間の差異を推測で補完しません。

- 2026.09以前のリリースでは `entity_list`・`software_list`・`attributions`・`reported_by`・`software_list` などは空です。
- 6.1.0でケーススタディの `actor` は任意項目になり、多くのケーススタディで帰属先は `attributions` に移りました。データに無い場合 `actor` は空文字列です。
- ケーススタディの日付は6.1.0で `date` から `start-date` / `end-date` に名称変更されたため、旧リリースの `date` は `start_date` として読み込みます。旧リリースの `end_date` は常に `None` です。

### Relationships

v6データのrelationshipは `get_relationships()` で起点、対象、種別を絞り込めます。種別は `achieves`、`specializes`、`mitigates`、`employs`、`sequences` と、6.1.0で追加された `attributed-to`、`reported-by`、`uses`、`implements` です。`attributed-to` などでは `activity_purpose` に活動目的が入ります。

```python
relationships = atlas.get_relationships(
    target_id="AML.T0000",
    type="mitigates",
)

for relationship in relationships:
    print(relationship.source_id, relationship.target_id)
```

### 検索

テクニック・緩和策・ケーススタディ・ケーススタディのステップを検索できます。Embedding providerが設定されている場合はベクトル検索(名前と説明文のcos類似度)、未設定の場合はキーワード検索(BM25)で順位を付け、結果はスコアの高い順に返します。

```python
from atlas import Atlas

atlas = Atlas(
    version="2026.10",
    emb_model="text-embedding-3-small",
    embedding_provider="openai",  # または "azure_openai"
)

techniques = atlas.search_relevant_techniques(
    query="malware that uses an LLM to generate commands",
    top_k=5,
    filter="both",            # parent / child / both
    tactic_id=None,           # 例: "AML.TA0002"
    platform=None,            # 例: "Agentic AI"
    maturity=None,            # "Feasible" / "Demonstrated" / "Realized"
)
mitigations = atlas.search_relevant_mitigations("prompt injection defenses", top_k=5)
case_studies = atlas.search_relevant_case_studies("attack by Russian state-sponsored group", top_k=3, casestudy_type="Incident")
steps = atlas.search_relevant_case_study_steps("uploading a malicious model to a public model hub", top_k=3)

for result in techniques:
    print(result.score, result.item.id, result.item.name)  # result.item は AtlasTechnique
```

検索結果は `AtlasSearchResult` のリストで、`item` に検索されたオブジェクト、`score` に0〜1の関連度が入ります。

- IDや名前と完全一致する場合(例: `"AML.T0051"`、`"LLM Prompt Injection"`)は、その項目がスコア1.0で最上位になります。それ以外のスコアは1.0未満です。
- ケーススタディは、名前・対象・帰属先エンティティ・使用ソフトウェア・概要が検索対象です。
- Embedding providerが未設定の場合はキーワード検索のみで動作します(`atlas.vector_search_enabled` が `False`)。

#### 検索精度に関する注意

- **英語のクエリを推奨します。** ATLASのデータは英語のため、日本語のクエリでは類似度が全体に低くなり、順位も不安定になります。例えば `text-embedding-3-small` で同じ内容を検索した場合、正解のテクニック (AML.T0102) のスコアは英語で約0.69、日本語で約0.46でした。日本語の「ロシアの国家支援グループによる攻撃」では正解のケーススタディが3位でしたが、英語の "attack by Russian state-sponsored group" では1位でした。AIエージェントのツールとして使う場合は、ツールの説明で英語での検索を指示すると効果的です。
- **キーワード検索のみの場合は精度が限られます。** 語形の違い(例: `LLM` と `LLMs`)を区別し、同義語も考慮しないため、自然文のクエリでは関連する項目を取りこぼすことがあります。可能な限りEmbedding providerを設定してください。
- **ベクトル検索とキーワード検索は混ぜていません。** 両方のスコアを合算する方式も試しましたが、ベクトル検索の類似度は候補間の差が小さく(0.01〜0.02程度)、"llm" などの一般的な語のキーワード一致で正しい順位が入れ替わることを確認したため採用していません。

### テキスト・辞書への変換 (AIエージェント向け)

検索結果と、`get_*_by_id` で取得した各オブジェクトは `to_text()` と `to_dict()` を持ちます。AIエージェントのツールとして使う場合、関連情報を含めた文字列をそのまま返せます。

```python
results = atlas.search_relevant_techniques("AML.T0102", top_k=1)
print(results[0].to_text())

atlas.get_case_study_by_id("AML.CS0044").to_text()
atlas.get_entity_by_id("AML.E0018").to_dict()   # JSONに変換可能な辞書
```

```text
## AML.T0102 Generate Malicious Commands  (score: 1.00)
Type: technique | Maturity: Realized | Platforms: Enterprise
Tactics: AML.TA0001 AI Attack Adaptation

Adversaries may use large language models (LLMs) to dynamically generate malicious commands ...

Mitigated by (2):
- AML.M0020 Generative AI Guardrails
- AML.M0022 Generative AI Model Alignment

Implemented by software (3):
- AML.S0015 LAMEHUG (Malware)
- AML.S0017 HONESTCUE (Malware)
- AML.S0018 Xanthorox (Tool)

Observed in case studies (4):
- AML.CS0044 LAMEHUG: Malware Leveraging Dynamic AI-Generated Commands
- ...
```

- 関連オブジェクトは1段階だけ「IDと名前」で展開します。詳細が必要な場合は、そのIDで再度 `get_*_by_id` を呼び出します。
- `to_text(max_related=10)` のように指定すると、関連オブジェクトの一覧ごとの表示件数を制限できます。
- `to_text()` ではマークダウンリンクと引用マーカー (`[[...]]`) を除去します。`to_dict()` は各属性の値をそのまま返します。

## MITRE ATT&CK

### 初期化とバージョン

ATT&CKではデータ構造に合わせて `enterprise`、`mobile`、`ics` のいずれかのdomainを指定します。`version`を省略すると、[`attack/data/manifest.yaml`](attack/data/manifest.yaml) に記載された最新バージョンを使用します。

データにはMITRE公式のSTIX 2.1データ ([mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)) をgzip圧縮して同梱しています。利用可能なバージョンは17.1・18.0・18.1・19.0・19.1・19.2・20.0・20.1です。廃止(revoked)・非推奨(deprecated)のオブジェクトは読み込みません。

```python
from attack import Attack

attack = Attack(version="20.1", domain="enterprise")
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
attack.relationships
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

STIXから取得できる次の情報も利用できます。

```python
technique = attack.get_technique_by_id("T1548.002")
print(technique.name)                    # Bypass User Account Control
print(technique.full_name)               # Abuse Elevation Control Mechanism: Bypass User Account Control
print(technique.parent.id, technique.platforms, technique.url)
print([t.id for t in attack.get_technique_by_id("T1548").subtechnique_list])

group = attack.get_group_by_id("G0007")
print(group.aliases)                     # 別名
print([s.name for s in group.software_list])   # 使用するソフトウェア
print([c.id for c in group.campaign_list])     # 帰属するキャンペーン

software = attack.get_software_by_id("S0001")
print(software.software_type, [g.id for g in software.group_list])

campaign = attack.get_campaign_by_id("C0001")
print(campaign.first_seen, campaign.last_seen, [g.id for g in campaign.group_list])
```

### Relationships

STIXのrelationshipは `get_relationships()` で起点、対象、種別を絞り込めます。主な種別は `uses`、`mitigates`、`subtechnique-of`、`attributed-to`、`detects`、`targets` (ICS) です。IDはATT&CK ID (例: `G0007`、`T1059.001`) です。

```python
for relationship in attack.get_relationships(source_id="G0007", type="uses"):
    print(relationship.target_id, relationship.target_type)
```

プロシージャ (`AttackProcedure`) はGroup・Software・Campaignからテクニックへの `uses` relationshipから、具体的な緩和策 (`AttackConcreteMitigation`) は `mitigates` relationshipから作成しています。

### セマンティック検索

先にOpenAIまたはAzure OpenAIの環境変数を設定します。

```python
from attack import Attack

attack = Attack(
    version="20.1",
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

ATLASの `search_relevant_techniques` と `search_relevant_case_study_steps` は、オブジェクトのリストではなく `AtlasSearchResult` のリストを返すように変更されました。従来のオブジェクトは `result.item` で取得できます。

```python
# 変更前
techniques = atlas.search_relevant_techniques("...", top_k=5)
# 変更後
techniques = [r.item for r in atlas.search_relevant_techniques("...", top_k=5)]
```

ATT&CKのデータはExcel版から公式STIX版に移行しました。内容はExcel版と一致することを全件比較で確認していますが、次の点が変わっています。

- エンタープライズのサブテクニックの `name` は、STIXの値どおりサブテクニック単体の名前になりました (例: `"Abuse Elevation Control Mechanism: Bypass User Account Control"` → `"Bypass User Account Control"`)。親テクニック名を含む名前は `full_name` で取得できます。
- プロシージャID (`P0001` など) の採番順が変わりました。そのため、ATT&CKのベクトルDBは新しい保存先 (`chroma-stix`) に作り直されます。
- 依存パッケージから `pandas` と `openpyxl` を削除しました。

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

単体テストは、APIキーが設定されていても有料のEmbedding APIを呼ばないようになっています。

### ATT&CKデータの更新

新しいATT&CKバージョンが公開されたら、次のスクリプトで公式STIXデータを取得します。`attack/data/v<version>/` にgzip圧縮したファイルが保存され、`manifest.yaml` の `latest` が最新バージョンに更新されます。

```bash
uv run python scripts/update_attack_data.py 20.1
```

### ブランチとリリース

- 開発は `main` ブランチ1本で行います。作業ブランチからmainへPRを作成すると、CI(lint・型チェック・Python 3.10〜3.13のテスト)が実行されます。
- リリースはGitHubの **Actions > Release > Run workflow** から、バージョン(例: `v1.2.0`)を入力して実行します。mainの最新コミットからビルドしたwheelをテストし、成功するとタグとGitHub Release(wheel・sdist添付)が作成されます。
- READMEのインストール手順に記載しているバージョン(`@vX.Y.Z` と `--tag vX.Y.Z`)は、リリース前のPRで更新してください。入力したバージョンと一致しない場合、Releaseワークフローはビルド前に失敗します。

## ライセンスとデータ

コードのライセンスは [LICENSE](LICENSE)、同梱するMITRE ATLASおよびMITRE ATT&CKデータの帰属情報は [NOTICE](NOTICE) を参照してください。
