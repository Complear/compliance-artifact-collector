# Compliance Artifact Collector

> **Open source under the Apache 2.0 licence**, published on the AI-on-Demand (AIoD) platform as
> part of the AGILE-AI programme.

The Collector gathers the compliance evidence of an AI system into one file, the **conformity
record**. Each piece of evidence is fingerprinted (SHA-256) and tagged with the framework clauses
it supports. The **EU AI Act** (Regulation (EU) 2024/1689) is scoped by the Collector itself;
other frameworks (ISO/IEC 42001, NIST AI RMF, your own) are carried as scopes and tags you supply
(step 4). You hand the record to an auditor, a notified body, or a compliance tool such as
Complear OS, which attaches each item to the matching obligation and shows what is still missing.

```
product.json ──► 1. scope         which AI Act tier applies, which clauses are in scope
             ──► 2. SBOM          models, datasets, libraries, licences
             ──► 3. signature     is the shipped container image signed?
             ──► 4. evaluations   test results (accuracy, robustness, bias)
             ──► 5. certificates  notified body, declaration of conformity, CE, registration
             ──► 6. TAI Scan      optional: AIoD TAI Scan's risk level, set against step 1
                                    │
                                    ▼
                         record.json (+ record.json.bundle when signed)
```

The Collector collects and tags. It does **not** decide whether the evidence is sufficient, and
it is not legal advice.

---

## 1. Install

You need two Complear repositories:
`Complear/compliance-artifact-collector` (this one) and `Complear/aiod-compliance-benchmark`
(it holds the EU AI Act rules the Collector uses for scoping). A record that leaves the AI Act out
(`"frameworks": []`) does not use the benchmark, so for that the Python install needs only `jsonschema`.

**Option A: Docker** (nothing else to install; the image includes cosign)

```sh
git clone https://github.com/Complear/compliance-artifact-collector.git
git clone https://github.com/Complear/aiod-compliance-benchmark.git
cd compliance-artifact-collector
make image          # builds compliance-artifact-collector:0.3.0
```

**Option B: Python 3.11+**

```sh
# the two clones side by side, as above
cd compliance-artifact-collector
make setup          # creates .venv with jsonschema and the benchmark engine
make test           # 11 tests, should print OK
```

Optional tools, used only if you ask for them:

| Tool | For | Install |
| --- | --- | --- |
| [syft](https://github.com/anchore/syft) | generating the SBOM | `brew install syft` |
| [cosign](https://github.com/sigstore/cosign) | checking image signatures, signing the record | `brew install cosign` (already in the Docker image) |

## 2. Try the example

```sh
.venv/bin/python -m cac collect examples/nodesight/product.json --out out/record.json
```

```
warning: signature-1: image signature not checked (no cosign key or identity configured)
out/record.json: 5 artefacts; eu_ai_act 35 clauses (tier high_risk_6_1)
```

`examples/nodesight/` is a **fictional** class IIb medical-imaging product; its company, notified
body and certificate numbers are made up. Copy that folder as the starting point for your own system.

With Docker, mount your folder at `/work`:

```sh
docker run --rm -v "$PWD/examples/nodesight:/work" compliance-artifact-collector:0.3.0 \
  collect product.json --out out/record.json
```

## 3. Describe your system: `product.json`

Every input is listed in one file. File paths are relative to `product.json`. Only `subject` is
required, plus either `facts` or `subject.description`; leave out any artefact you do not have yet.

```json
{
  "subject": {
    "name": "NodeSight",
    "version": "2.3.0",
    "provider": "Example Imaging Ltd",
    "intended_purpose": "Segments lung nodules on chest CT and reports a malignancy likelihood to the radiologist.",
    "description": "Free text describing what the system does, used when facts are not given.",
    "language": "en"
  },
  "facts": { "...": "see step 4" },
  "sbom": "sbom.cdx.json",
  "image": { "ref": "registry.example.com/nodesight", "digest": "sha256:<64 hex>", "cosign": { "key": "cosign.pub" } },
  "evaluations": [ "scorecard.json", { "junit": "report.xml", "name": "...", "supports": [] } ],
  "certificates": [ { "kind": "declaration_of_conformity", "issuer": "Example Imaging Ltd", "number": "DoC-1" } ]
}
```

`subject.language` (a BCP 47 tag such as `de` or `pt-PT`, default `en`) is the language of your
texts. The titles the Collector writes follow it in English, German, French, Spanish, Italian,
Portuguese, Dutch and Polish; any other language gets English titles. Names, issuers and tool
output stay as you wrote them. Complear OS shows the rest of each item in its reader's language.

## 4. Scope

### Other frameworks

Only the EU AI Act is scoped by the Collector (`"frameworks": ["eu_ai_act"]`, the default). For
any other framework, put the scope you or another tool decided under `"scopes"`. It is carried as
given, with `"method": "supplied"`:

```json
"scopes": [
  {"framework": {"key": "iso42001", "version": "2023"},
   "answers": {"organisation_role": "AI provider"},
   "clauses": ["6.1.2", "8.2", "9.1"]}
]
```

`key` is the framework's key in Complear OS (the pack key, in lower case). Tag evidence with
`"<key>:<citation>"`, for example `"iso42001:9.1"`. A bare citation such as `"Art.15(3)"` means
the EU AI Act. Set `"frameworks": []` to leave the AI Act out.

### The AI Act: 11 facts

The Collector decides the AI Act tier and the clauses in scope from 11 facts about your system.
**Give them yourself** in `"facts"` (recommended), or leave `"facts"` out and let a language model
read them from `subject.description` (see step 10).

| Fact | Values | Set it to true / a value when |
| --- | --- | --- |
| `ai_system` | true/false | the system infers outputs (predictions, recommendations, content, decisions) with machine learning or another learned method. Fixed hand-written rules are false. |
| `prohibited_practice` | true/false | it does something Art. 5 bans: harmful manipulation, exploiting vulnerabilities, social scoring, crime prediction from profiling alone, untargeted face scraping, emotion recognition of workers or students (non-medical), biometric inference of sensitive traits, real-time remote identification in public for law enforcement. |
| `mdr_class` | `none`, `I`, `IIa`, `IIb`, `III` | it is a medical device; use its MDR class. |
| `annex_iii_area` | `none`, `biometrics`, `critical_infrastructure`, `education`, `employment`, `essential_services`, `law_enforcement`, `migration`, `justice_democracy` | it is used in an Annex III area. Emergency patient triage and health-insurance pricing are `essential_services`. |
| `art6_3_exception` | true/false | (only with an Annex III area) it only does a narrow procedural task, improves finished human work, flags patterns for a human, or prepares a human decision. |
| `profiling` | true/false | it automatically evaluates personal aspects of individuals (health, behaviour, reliability, performance). Profiling cancels the Art. 6(3) exception. |
| `special_category_data` | true/false | sensitive data (health, biometric…) is processed **specifically to detect or correct bias**. Training on it alone is false. |
| `remote_biometric_id` | true/false | it identifies people at a distance against a database. One-to-one identity confirmation is false. |
| `interacts_with_persons` | true/false | people talk or chat with it directly. |
| `synthetic_content` | true/false | it generates text, images, audio or video. |
| `emotion_or_biometric_categorisation` | true/false | it recognises emotions or sorts people by biometric data. |

Tiers in the record: `out_of_scope`, `prohibited`, `high_risk_6_1` (regulated product such as an MDR
class IIa+ device), `high_risk_6_2` (Annex III), `limited` (transparency duties only), `minimal`.

## 5. SBOM

Generate a CycloneDX JSON SBOM of your shipped image (or source tree) and point `"sbom"` at it:

```sh
syft registry.example.com/nodesight@sha256:<digest> -o cyclonedx-json > sbom.cdx.json
# or for a folder:  syft dir:. -o cyclonedx-json > sbom.cdx.json
```

The Collector records the component count, licences, and every component of CycloneDX type
`machine-learning-model` and `data`. Scanners rarely know which files are models or datasets: add
them by hand to `components` if they are missing, for example

```json
{"type": "data", "name": "training-ct-scans", "version": "2025-09", "licenses": [{"license": {"name": "Proprietary"}}]}
```

Declaring a dataset adds Art. 10(2) (data governance) to the SBOM's tags. Only CycloneDX is read;
convert SPDX first.

## 6. Image signature

Give the image and its **digest** (never only a tag; tags can be moved):

```sh
docker buildx imagetools inspect registry.example.com/nodesight:2.3.0 --format '{{json .Manifest.Digest}}'
```

Then say how it was signed:

| You signed with | `"cosign"` value |
| --- | --- |
| a key pair (`cosign sign --key cosign.key …`) | `{"key": "cosign.pub"}` |
| keyless, from CI (e.g. GitHub Actions) | `{"identity": "https://github.com/ORG/REPO/.github/workflows/release.yml@refs/heads/main", "issuer": "https://token.actions.githubusercontent.com"}` |

The record says `verified: true`, `false` (the check failed; the Collector warns) or `null` (not
checked: no cosign, or no key/identity given). Checking needs network access to your registry.

## 7. Evaluations

Three forms:

- **A benchmark scorecard** (schema 0.1), e.g. from the compliance benchmark's `make scorecard`:
  list its path, `"evaluations": ["scorecard.json"]`. Metrics and clause tags are taken from it.
  Its limitations are preserved in the record’s `limitations`, prefixed with the evaluation’s artefact id.
- **A test report**, JUnit XML or [CTRF](https://ctrf.io) JSON, from any test runner in any
  language (pytest `--junitxml`, Jest, JUnit, Go `gotestsum`, …):
  `{"junit": "report.xml", "name": "Robustness suite", "supports": ["Art.15(4)"]}`, or `"ctrf": "ctrf.json"`.
  The record keeps the counts (`tests`: total, passed, failed, skipped) and a `pass_rate` metric.
  CTRF `pending` and `other` outcomes are included in `skipped`; the reported `passed` count
  is preserved. The pass rate excludes skipped outcomes; no rate is emitted when all tests are skipped.
- **An AI Testing Framework (AITF) run**: point at the executed module in the AITF data folder,
  `{"aitf": "data/modules/<run>/module.json", "supports": ["Art.9(2)"]}`. Its `file:///data/`
  locations resolve against that folder. A `scorecard.json` beside the run's `evaluation.json`
  supplies the metrics and clause tags; without one, every numeric metric of the evaluation is
  taken. `data.aitf` records the run: the executed module and template SHA-256, the payload id of
  every input and output artifact, and the image of each step. `examples/aitf` is a sample run.
- **Any other test** (TAI Scan, your own validation): enter it inline.

```json
{
  "tool": "AI Testing Framework",
  "name": "Nodule detection, held-out test set",
  "version": "2026-11",
  "date": "2026-11-10",
  "metrics": [
    {"name": "sensitivity", "value": 0.94, "n": 1200, "higher_is_better": true},
    {"name": "sensitivity_gap_by_sex", "value": 0.02, "n": 1200, "higher_is_better": false}
  ],
  "supports": ["Art.15(1)", "Art.15(3)", "Art.4a(1)", "Annex IV(2)(g)"]
}
```

`supports` lists the clauses the result is evidence for (accuracy: Art. 15(1)/(3); robustness:
Art. 15(4); bias: Art. 4a(1), formerly Art. 10(5); test documentation: Annex IV(2)(g)). Add other frameworks' clauses
as `"iso42001:9.1"`.

A single check with a pass/fail outcome needs no metrics: give `"result"` (`"pass"`, `"fail"`, or
anything else, such as `"inconclusive"`, which is recorded as skipped) and the record keeps it as a
one-test count. Add `"file"` (relative to `product.json`) to fingerprint the check's own evidence file.

```json
{"tool": "AI Coding Tool Validation Kit", "name": "OQ-01 gates", "date": "2026-11-16",
 "result": "pass", "file": "evidence/CLAUDE/OQ-01/gates.json",
 "supports": ["ai_coding_tool_validation:OQ-01"]}
```

### Evidence from the AI Coding Tool Validation Kit

The [AI Coding Tool Validation Kit](https://github.com/bernardopersonal/ai-coding-tool-validation-kit)
validates AI coding assistants (Claude Code, Codex) under ISO 13485:2016 4.1.6. Its scripts write
JSON evidence under `evidence/<TOOL>/<TEST-ID>/`. `examples/ai-tool-validation/kit_product.py`
turns those folders into a `product.json`, one evaluation per evidence file, tagged with its test id
in Complear's `ai_coding_tool_validation` framework:

```sh
python3 examples/ai-tool-validation/kit_product.py evidence/CLAUDE evidence/GEN \
  --name "Claude Code" --version 2.1.0 --provider Anthropic --profile lite --out product.json
.venv/bin/python -m cac collect product.json --out record.json
.venv/bin/python -m cac push record.json
```

Use a Complear upload key on the branch where the `ai_coding_tool_validation` framework is applied;
a test id that is not applied there comes back as `unmatched`. `examples/ai-tool-validation/` holds
fictional evidence and the record it produces.

## 8. Certificates

```json
{"kind": "notified_body_certificate", "issuer": "Your Notified Body", "notified_body_id": "1234",
 "number": "MDR-0042", "regulation": "MDR (EU) 2017/745 Annex IX",
 "valid_from": "2025-03-01", "valid_until": "2030-02-28", "file": "certificate.pdf"}
```

| `kind` | Default tag |
| --- | --- |
| `notified_body_certificate` | Art. 43(3) |
| `declaration_of_conformity` | Art. 47(1) |
| `ce_marking` | Art. 48 |
| `eu_database_registration` | Art. 49(1) |

`file` is optional; when given, its SHA-256 goes into the record. `notified_body_id` is the
four-digit NANDO number. Dates are `YYYY-MM-DD`.

## 8a. A second opinion: AIoD TAI Scan

Add a `tai_scan` block with TAI Scan's five fields and the record gets a `classification-1`
artefact: TAI Scan's risk level in its own words, mapped to a tier, its relevant articles, and
whether it agrees with the scope's tier. A disagreement becomes a limitation for a person to
resolve; TAI Scan never changes the scope.

```json
"tai_scan": {"role": "provider", "domain": "healthcare", "type": "medical device software",
             "input_data": "chest CT images", "intended_use": "detects and measures lung nodules"}
```

```sh
TAI_USER=... TAI_PASS=... python -m cac collect product.json --out out/record.json
```

`TAI_USER` and `TAI_PASS` are your AIoD account (the one you sign in with on the AIoD
marketplace); they go only to `aiodp-auth.aiodp.ai`. If that login is refused ("Invalid user
credentials") although the web form accepts you, sign in at https://tai-scan.aiodp.ai, run
`copy(sessionStorage.getItem("keycloak_token"))` in the browser console, and pass it as
`TAI_TOKEN` instead; it lasts a few minutes, enough for one record.
To collect offline, put a saved answer in the block: `"answer": {"level": "...", "articles": "..."}`.
Complear OS accepts `classification` artefacts from the version that lists the type; an older one
refuses the record.

## 9. Run, read the output, sign

```sh
python -m cac collect product.json --out out/record.json
python -m cac validate out/record.json        # prints "valid"
```

The record (`schema/conformity-record.schema.json`, version 0.3):

| Part | Holds |
| --- | --- |
| `record_id`, `created_at`, `collector` | a unique id, UTC time, Collector version |
| `subject` | name, version, provider, intended purpose, language |
| `scopes[]` | per framework: `framework` (key, version), `method` (`facts_supplied`, `reader` or `supplied`), `answers` to its scoping questions, `clauses` in scope; for the AI Act also the facts and `tier` |
| `artefacts[]` | `id` (`sbom-1`, `evaluation-2`, `classification-1`…), `type`, `title`, `supports` (`{framework, citation}` pairs), `source` (path + SHA-256), `data` |
| `limitations` | caveats, e.g. facts extracted by a language model |

**Gaps** are the clauses in a scope that no artefact `supports`. The Collector does not list
them; Complear OS (or a `jq` one-liner) does:

```sh
jq -r '[.artefacts[].supports[] | "\(.framework) \(.citation)"] as $s
       | .scopes[] | .framework.key as $f | .clauses[] | "\($f) \(.)" | select(. as $c | $s | index($c) | not)' out/record.json
```

**Sign the record** so a recipient can check it was not changed:

```sh
cosign generate-key-pair                                   # once; keep cosign.key secret
python -m cac collect product.json --out out/record.json --sign-key cosign.key
cosign verify-blob --key cosign.pub --bundle out/record.json.bundle --insecure-ignore-tlog out/record.json
```

Send `record.json`, `record.json.bundle` and `cosign.pub`. Signing is offline by default.
`--transparency-log` also writes the signature to the **public** Sigstore log, which publishes the
record's hash, the signature and your public key (not the record's content); use it only if you
want that public timestamp.

**Send it to Complear OS.** In Complear, an admin turns on *Conformity records API* for the
workspace. You then create an API key in *Settings → API keys* with the purpose
*Conformity record upload*, choosing the Project (the AI system) and *Project Documentation*.

```sh
export COMPLEAR_URL=https://<workspace>.complear.com COMPLEAR_UPLOAD_KEY=ck_live_...
python -m cac push out/record.json
```

Each artefact becomes a Project Documentation item, offered for review (never approved) and
connected to the Project's applied requirement for each tag. The reply lists what was `recorded`,
`duplicate` (sending the same record again is safe), `unmatched` tags, and the `scopes` whose
answers differ from those recorded in Complear. Complear never changes what applies; a person
does. A changed artefact under the same `record_id` is refused (409); collect a new record.

## 10. Letting a language model read the facts

Leave `"facts"` out and write a plain `subject.description`. The Collector then calls an
OpenAI-compatible endpoint:

```sh
# a local Ministral 3B, from the benchmark repo
(cd ../aiod-compliance-benchmark && make serve)            # http://127.0.0.1:8080/v1
READER_URL=http://127.0.0.1:8080/v1 python -m cac collect product.json --out out/record.json
# the example without facts: examples/nodesight/product-reader.json
# any other endpoint: READER_URL=..., READER_MODEL=..., READER_API_KEY=...
```

The record then says `"method": "reader"` and carries a limitation: **a person must confirm the
facts.** The description may be in any language the model reads; the benchmark measures English
only, so confirm the facts with extra care for other languages. On the benchmark, the small baseline model over-claims the Art. 6(3) exception; check that
fact in particular. In Docker, pass the variables with `-e` and make sure the container can reach
the endpoint.

## 11. Warnings and errors

| Message | Meaning, what to do |
| --- | --- |
| `signature-1: image signature not checked (…)` | no cosign or no key/identity: add `"cosign"` (step 6) |
| `signature-1: image signature failed verification (…)` | the image is not signed by that key/identity; the record still says `verified: false` |
| `… supports Art.99(1), which is not a clause of the EU AI Act pack` | a typo or a clause outside the pack; citations look like `Art.15(3)`, `Art.48`, `Annex IV(2)(g)` |
| `… supports iso42001, which no scope in this record covers` | add that framework under `"scopes"`, or fix the `"<key>:"` prefix |
| `error: frameworks: iso42001 has no built-in scoping` | only `eu_ai_act` is built in; move it to `"scopes"` |
| `error: facts: bad value mdr_class='IV'` | a fact outside its allowed values (step 4) |
| `error: …: not a CycloneDX JSON SBOM` | the SBOM is SPDX or another format; regenerate with `-o cyclonedx-json` |
| `error: --sign-key needs cosign on PATH` | install cosign, or use the Docker image |

## Limits

- TAI Scan results are entered by hand (or as JUnit/CTRF) until its output format is mapped.
- Only the EU AI Act is scoped by the Collector; other frameworks' scopes are carried as supplied.
- The default clause tags are Complear's reading of the AI Act; change any artefact's `supports`
  in `product.json` if your assessment differs.
- Not scoped: MDR class I devices that need a notified body, IVDR devices, general-purpose AI models.
- Image signature checking is tested against a stub; record signing and verification are tested
  with cosign 2.4.1.

## Licence

To be released under Apache 2.0 (see `LICENSE`). Built by Complear for AIoD, programme AGILE-AI.
