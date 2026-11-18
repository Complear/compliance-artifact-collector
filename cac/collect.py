"""Compliance Artifact Collector: gather an AI system's compliance artefacts into one conformity record.

    python -m cac collect product.json --out record.json [--sign-key cosign.key]

product.json names the subject and the artefact files (paths are relative to product.json):

    {"subject": {"name", "version", "provider", "intended_purpose", "description", "language"},
     "facts": {...11 facts...},          # optional: without it the reader extracts them from "description"
     "frameworks": ["eu_ai_act"],        # built-in scoping (default); only the EU AI Act ships open
     "scopes": [{"framework": {"key", "version"}, "answers", "clauses"}],  # other frameworks, decided elsewhere
     "sbom": "sbom.cdx.json",            # CycloneDX JSON, e.g. `syft <image> -o cyclonedx-json`
     "image": {"ref": "...", "digest": "sha256:...", "cosign": {"key": "cosign.pub"}
                                                  # or {"identity": "...", "issuer": "..."}},
     "evaluations": ["scorecard.json", {"tool", "name", "metrics": [...], "result", "file", "supports": [...]},
                     {"junit": "report.xml" | "ctrf": "ctrf.json", "name", "supports": [...]},
                     {"aitf": "<data>/modules/<run>/module.json", "supports": [...]}],  # an executed AITF module
     "certificates": [{"kind", "issuer", "number", ...}],
     "tai_scan": {"role", "domain", "type", "input_data", "intended_use",  # AIoD TAI Scan's five fields
                  "answer": {...}}}  # optional: a saved TAI Scan answer; without it, TAI_USER/TAI_PASS call the API

EU AI Act scope comes from the engine of the compliance benchmark (`cdb`): facts -> tier -> the
pack's scoping answers and clauses. Other frameworks are carried as supplied scopes. A `supports`
tag is `{framework, citation}`; in product.json write "Art.15(3)" (EU AI Act) or "iso42001:8.2".
Each artefact is tagged with what it is evidence for; deciding whether that evidence is sufficient
is left to the consumer (Complear OS or any other tool).
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from cac import __version__
from cac.i18n import title

SCHEMA = json.loads((Path(__file__).resolve().parent.parent / "schema" / "conformity-record.schema.json").read_text())

AI_ACT = "eu_ai_act"
# Default clauses each artefact kind is evidence for (EU AI Act pack citations).
SBOM_SUPPORTS = ["Art.11(1)", "Art.15(5)"]          # technical documentation; cybersecurity (supply chain)
SBOM_DATASET_SUPPORTS = ["Art.10(2)"]               # data governance, when datasets are declared
SIGNATURE_SUPPORTS = ["Art.15(5)", "Art.17(1)"]     # integrity of the shipped system; QMS version control
CERTIFICATE_SUPPORTS = {
    "notified_body_certificate": ["Art.43(3)"],     # product route: MDR conformity assessment covers the AI Act
    "declaration_of_conformity": ["Art.47(1)"],
    "ce_marking": ["Art.48"],
    "eu_database_registration": ["Art.49(1)"],
}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _source(path, base):
    return {"path": str(Path(path)), "sha256": sha256(base / path)}


def tags(values, default=AI_ACT):
    """product.json tags ("Art.15(3)", "iso42001:8.2", or {framework, citation}) as {framework, citation}."""
    out = []
    for v in values:
        if isinstance(v, dict):
            out.append({"framework": v["framework"], "citation": v["citation"]})
        elif m := re.match(r"^([a-z0-9_]+):(.+)$", v):
            out.append({"framework": m[1], "citation": m[2]})
        else:
            out.append({"framework": default, "citation": v})
    return sorted({(t["framework"], t["citation"]): t for t in out}.values(), key=lambda t: (t["framework"], t["citation"]))


def ai_act_scope(config, read=None):
    """(scope, limitations) for the EU AI Act. `read` extracts facts from text; defaults to the benchmark reader."""
    limitations = []
    facts = config.get("facts")
    method = "facts_supplied"
    if facts is None:
        if read is None:
            from cdb import reader
            read = reader.read
        facts, ok = read(config["subject"]["description"])
        method = "reader"
        if not ok:
            limitations.append("The reader returned no valid facts; scope uses default facts and is not reliable.")
        limitations.append("Facts were extracted by a language model from the description; a person should confirm them.")
    from cdb import engine, pack  # the benchmark is needed only when the collector scopes the AI Act itself

    problems = engine.validate(facts)
    if problems:
        raise ValueError(f"facts: {'; '.join(problems)}")
    framework = pack.load()["framework"]
    decision = engine.decide(facts)
    block = {"framework": {"key": framework["key"], "version": framework["version"]}, "method": method,
             "answers": engine.answers(facts), "facts": facts, "tier": decision["tier"], "clauses": decision["clauses"]}
    return block, limitations


# Frameworks the collector scopes itself. ponytail: one entry; a framework added here needs its own engine.
FRAMEWORKS = {AI_ACT: ai_act_scope}


def scopes(config, read=None):
    """(scopes, limitations): the built-in frameworks named in config, then the supplied ones."""
    blocks, limitations = [], []
    for key in config.get("frameworks", [AI_ACT]):
        if key not in FRAMEWORKS:
            raise ValueError(f"frameworks: {key} has no built-in scoping; supply it under \"scopes\"")
        block, notes = FRAMEWORKS[key](config, read)
        blocks.append(block)
        limitations += notes
    for s in config.get("scopes", []):
        blocks.append({"framework": s["framework"], "method": "supplied", "answers": s.get("answers", {}),
                       "clauses": s.get("clauses", [])})
    keys = [b["framework"]["key"] for b in blocks]
    if len(keys) != len(set(keys)):
        raise ValueError("scopes: a framework is scoped twice")
    return blocks, limitations


def sbom_artefact(path, base, lang="en"):
    """Summarise a CycloneDX JSON SBOM: models and datasets (CycloneDX 1.5+ ML-BOM types) and licences."""
    doc = json.loads((base / path).read_text())
    if doc.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path}: not a CycloneDX JSON SBOM")

    def flat(components):
        for c in components or []:
            yield c
            yield from flat(c.get("components"))

    def licenses(c):
        out = []
        for entry in c.get("licenses", []):
            lic = entry.get("license", {})
            name = lic.get("id") or lic.get("name") or entry.get("expression")
            if name:
                out.append(name)
        return out

    def entry(c):
        e = {"name": c.get("name", "?")}
        if c.get("version"):
            e["version"] = c["version"]
        if licenses(c):
            e["licenses"] = licenses(c)
        return e

    comps = list(flat(doc.get("components")))
    models = [entry(c) for c in comps if c.get("type") == "machine-learning-model"]
    datasets = [entry(c) for c in comps if c.get("type") == "data"]
    supports = SBOM_SUPPORTS + (SBOM_DATASET_SUPPORTS if datasets else [])
    data = {"format": f"CycloneDX {doc.get('specVersion', '?')}", "components": len(comps), "models": models,
            "datasets": datasets, "licenses": sorted({lic for c in comps for lic in licenses(c)})}
    return {"type": "sbom", "title": title(lang, "sbom", components=len(comps), models=len(models), datasets=len(datasets)),
            "supports": tags(supports), "source": _source(path, base), "data": data}


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def signature_artefact(image, base, run=_run, which=shutil.which, lang="en"):
    """Verify the image signature with cosign when it is installed and a key or identity is given."""
    ref, digest, cfg = image["ref"], image["digest"], image.get("cosign") or {}
    repo, _, last = ref.split("@")[0].rpartition("/")
    target = f"{repo + '/' if repo else ''}{last.split(':')[0]}@{digest}"  # verify the digest, never a movable tag
    if "key" in cfg:
        method, args = "cosign-key", ["--key", str(base / cfg["key"])]
    elif "identity" in cfg and "issuer" in cfg:
        method, args = "cosign-keyless", ["--certificate-identity", cfg["identity"], "--certificate-oidc-issuer", cfg["issuer"]]
    else:
        method, args = "none", None

    if args is None:
        verified, detail = None, "no cosign key or identity configured"
    elif not which("cosign"):
        verified, detail = None, "cosign is not installed"
    else:
        result = run(["cosign", "verify", *args, target])
        verified = result.returncode == 0
        detail = "signature verified" if verified else (result.stderr.strip().splitlines() or ["verification failed"])[-1]
    data = {"image": ref, "digest": digest, "verified": verified, "method": method, "detail": detail}
    key = {True: "signature_verified", False: "signature_failed", None: "signature_unchecked"}[verified]
    return {"type": "signature", "title": title(lang, key), "supports": tags(SIGNATURE_SUPPORTS), "data": data}


def test_summary(item, base):
    """{total, passed, failed, skipped} from a JUnit XML or CTRF JSON report."""
    if "ctrf" in item:
        summary = json.loads((base / item["ctrf"]).read_text())["results"]["summary"]
        # Schema 0.3 has four counts: group pending and other outcomes under skipped.
        counts = {"total": summary["tests"], "passed": summary["passed"], "failed": summary["failed"],
                  "skipped": sum(summary.get(status, 0) for status in ("skipped", "pending", "other"))}
    else:
        root = ET.parse(base / item["junit"]).getroot()
        cases = list(root.iter("testcase"))
        counts = {"total": len(cases),
                  "failed": sum(1 for c in cases if c.find("failure") is not None or c.find("error") is not None),
                  "skipped": sum(1 for c in cases if c.find("skipped") is not None)}
        counts["passed"] = counts["total"] - counts["failed"] - counts["skipped"]
    return counts


def _digest(ref):
    return ref["id"]["digest"]


def aitf_artefact(item, base, lang="en"):
    """An executed AITF module (`<data>/modules/<run>/module.json`): its evaluation, with the run's provenance.

    The module's file:///data/ locations resolve against the data folder the module sits in. A
    scorecard (schema 0.1) next to evaluation.json supplies the metrics and their AI Act clauses;
    without one, every numeric metric of the evaluation groups is taken and `supports` comes from
    the item.
    """
    module_path = base / item["aitf"]
    module = json.loads(module_path.read_text())
    if module.get("type") != 1:
        raise ValueError(f"{item['aitf']}: expected an executed AITF module (type 1), not a template")
    root = module_path.parent.parent.parent
    name = module["uuid"]["name"]

    def local(uri):
        if not uri.startswith("file:///data/"):
            raise ValueError(f"{item['aitf']}: {uri} is not under file:///data/")
        path = (root / uri.removeprefix("file:///data/")).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError(f"{item['aitf']}: {uri} leaves the data folder")
        return path

    nodes = module["graph"]["nodes"]
    artifacts = [n for n in nodes if "node_type" in n]
    [evaluation] = [n for n in artifacts if n["node"] == item.get("node", "evaluation")]
    eval_path = local(evaluation["location"]["uri"])
    scorecard = eval_path.parent / "scorecard.json"
    if scorecard.exists():
        art = evaluation_artefact(str(scorecard), base, lang)
        art["data"]["tool"] = f"AITF: {art['data']['tool']}"
        art["supports"] += tags(item.get("supports", []))
    else:
        groups = json.loads(eval_path.read_text())["evaluations"]
        metrics = [{"name": f"{g['name']}: {k}", "value": m["value"]} for g in groups
                   for k, m in g["metrics"].items() if isinstance(m.get("value"), (int, float))]
        art = {"type": "evaluation", "title": f"AITF: {name}", "supports": tags(item.get("supports", [])),
               "data": {"tool": "AITF", "name": name, "metrics": metrics}}
    art["source"] = {"path": str(eval_path.relative_to(root.resolve())), "sha256": sha256(eval_path)}

    execution_path = root / "executions" / name / "execution.json"
    execution = json.loads(execution_path.read_text()) if execution_path.exists() else {}
    if execution.get("finish") and "date" not in art["data"]:
        art["data"]["date"] = datetime.fromtimestamp(execution["finish"] / 1e9, timezone.utc).date().isoformat()
    art["data"]["aitf"] = {
        "execution": name,
        "module_sha256": _digest(module["uuid"]),
        **({"template": execution["template"]["name"], "template_sha256": _digest(execution["template"]),
            "state": execution["state"]} if execution else {}),
        "artifacts": [{"name": n["node"], "payload_id": n["payload_id"], "output": n["node_type"] == 1}
                      for n in artifacts if n.get("payload_id")],
        "steps": [{"name": n["node"], "image": n["location"]["uri"]} for n in nodes if "environment" in n],
        "modules": {k: _digest(m) for k, m in module["graph"].get("modules", {}).items()},
    }
    return art


def evaluation_artefact(item, base, lang="en"):
    """A benchmark scorecard (schema 0.1), a JUnit/CTRF test report, an AITF run, or an inline evaluation."""
    if isinstance(item, dict) and "aitf" in item:
        return aitf_artefact(item, base, lang)
    if isinstance(item, str):
        card = json.loads((base / item).read_text())
        if card.get("schema_version") != "0.1":
            raise ValueError(f"{item}: expected a scorecard with schema_version 0.1")
        b = card["benchmark"]
        metrics = [{k: m[k] for k in ("name", "value", "n", "higher_is_better") if k in m} for m in card["metrics"]]
        data = {"tool": card["subject"]["system"], "name": b["name"], "version": b["version"],
                "dataset_sha256": b["dataset_sha256"], "date": card["run"]["date"], "metrics": metrics}
        supports = [ref for m in card["metrics"] for ref in m["ai_act_refs"]]
        art = {"type": "evaluation", "title": f"{b['name']} {b['version']} ({b.get('split', 'all')})",
               "supports": tags(supports), "source": _source(item, base), "data": data}
        if card.get("limitations"):
            art["limitations"] = [card["limitations"]]
        return art
    if "junit" in item or "ctrf" in item:
        path = item.get("junit") or item.get("ctrf")
        counts = test_summary(item, base)
        run = counts["total"] - counts["skipped"]
        metrics = [{"name": "pass_rate", "value": round(counts["passed"] / run, 4), "n": run,
                    "higher_is_better": True}] if run else []
        data = {"tool": item.get("tool", "JUnit" if "junit" in item else "CTRF"), "name": item["name"],
                "tests": counts, "metrics": metrics}
        return {"type": "evaluation", "title": title(lang, "tests", name=item["name"], **counts),
                "supports": tags(item.get("supports", [])), "source": _source(path, base), "data": data}
    # Inline form: a tool's metrics written into product.json. TAI Scan has its own key ("tai_scan").
    data = {k: item[k] for k in ("tool", "name", "version", "dataset_sha256", "date", "metrics") if k in item}
    if "result" in item:  # one check's outcome: "pass", "fail", or anything else (inconclusive) as skipped
        outcome = {"pass": "passed", "fail": "failed"}.get(item["result"], "skipped")
        data["tests"] = {"total": 1, "passed": 0, "failed": 0, "skipped": 0, outcome: 1}
    name = f"{item['tool']}: {item['name']}"
    art = {"type": "evaluation", "title": title(lang, "tests", name=name, **data["tests"]) if "tests" in data else name,
           "supports": tags(item.get("supports", [])), "data": data}
    if item.get("file"):
        art["source"] = _source(item["file"], base)
    return art


def certificate_artefact(item, base, lang="en"):
    data = {k: v for k, v in item.items() if k not in ("file", "supports")}
    art = {"type": "certificate", "title": title(lang, item["kind"], issuer=item["issuer"]),
           "supports": tags(item.get("supports", CERTIFICATE_SUPPORTS[item["kind"]])), "data": data}
    if item.get("file"):
        art["source"] = _source(item["file"], base)
    return art


def classification_artefact(item, scope_blocks, lang="en", client=None, today=None):
    """AIoD TAI Scan's risk level for the five fields, set against the engine's tier.

    TAI Scan is a second opinion: its answer is recorded with the engine's tier, and a disagreement
    becomes a limitation for a person to resolve. Neither one changes the scope.
    """
    from cdb import taiscan
    fields = {k: item[k] for k in ("role", "domain", "type", "input_data", "intended_use")}
    answer = item.get("answer")
    if answer is None:
        if not (os.environ.get("TAI_TOKEN") or (os.environ.get("TAI_USER") and os.environ.get("TAI_PASS"))) and client is None:
            raise ValueError("tai_scan: set TAI_TOKEN, or TAI_USER and TAI_PASS (an AIoD account), or supply its \"answer\"")
        client = client or taiscan.Client()
        answer = {**client.call("risk_level", fields), **client.call("relevant_resources", fields)}
    ai_act = next((b for b in scope_blocks if b["framework"]["key"] == AI_ACT), None)
    engine_tier = taiscan.TIERS[ai_act["tier"]] if ai_act and "tier" in ai_act else None
    tier = taiscan.level_to_tier(answer.get("level"))
    data = {"tool": "AIoD TAI Scan", "service": taiscan.API, "date": (today or datetime.now(timezone.utc).date()).isoformat(),
            "input": fields, "level": str(answer.get("level", "")).strip(), "tier": tier,
            "articles": sorted(taiscan.articles(str(answer.get("articles", ""))), key=lambda a: (len(a), a))}
    for k in ("annexes", "recitals"):  # TAI Scan sends lists as text: "['VIII', 'III', 'VIII']"
        if answer.get(k):
            data[k] = ", ".join(dict.fromkeys(re.findall(r"[0-9A-Za-z]+", str(answer[k]))))
    if answer.get("obligations"):
        data["obligations"] = str(answer["obligations"])
    art = {"type": "classification", "title": title(lang, "tai_scan", level=data["level"] or "?"),
           "supports": tags([c for c in (ai_act or {}).get("clauses", []) if c.startswith("Art.6(")]), "data": data}
    if engine_tier:
        data["engine_tier"], data["agrees"] = engine_tier, tier == engine_tier
        if tier != engine_tier:
            art["limitations"] = [f"TAI Scan reads the risk level as {tier}, the engine as {engine_tier}; a person should decide."]
    return art


def collect(config, base=Path("."), read=None, run=_run, which=shutil.which, now=None):
    """Returns (record, warnings). Raises ValueError or jsonschema.ValidationError on bad input."""
    base = Path(base)
    lang = config["subject"].get("language", "en")
    scope_blocks, limitations = scopes(config, read)
    artefacts = []
    if config.get("sbom"):
        artefacts.append(sbom_artefact(config["sbom"], base, lang))
    if config.get("image"):
        artefacts.append(signature_artefact(config["image"], base, run, which, lang))
    artefacts += [evaluation_artefact(e, base, lang) for e in config.get("evaluations", [])]
    artefacts += [certificate_artefact(c, base, lang) for c in config.get("certificates", [])]
    if config.get("tai_scan"):
        artefacts.append(classification_artefact(config["tai_scan"], scope_blocks, lang))

    counts = {}
    for art in artefacts:
        counts[art["type"]] = counts.get(art["type"], 0) + 1
        art["id"] = f"{art['type']}-{counts[art['type']]}"
        limitations.extend(f"{art['id']}: {note}" for note in art.get("limitations", []))

    scoped = {b["framework"]["key"] for b in scope_blocks}
    ai_act_tags = [(a, t) for a in artefacts for t in a["supports"] if t["framework"] == AI_ACT]
    known = set()
    if ai_act_tags:
        from cdb import pack
        known = set(pack.leaves())
    warnings = [f"{a['id']} supports {t['citation']}, which is not a clause of the EU AI Act pack"
                for a, t in ai_act_tags if t["citation"] not in known and not t["citation"].startswith("Annex ")]
    warnings += [f"{a['id']} supports {t['framework']}, which no scope in this record covers"
                 for a in artefacts for t in a["supports"] if t["framework"] not in scoped]
    warnings += [f"{a['id']}: {a['title'].lower()} ({a['data']['detail']})"
                 for a in artefacts if a["type"] == "signature" and a["data"]["verified"] is not True]

    subject = {k: v for k, v in config["subject"].items()
               if k in ("name", "version", "provider", "intended_purpose", "language")}
    record = {
        "schema_version": "0.3",
        "record_id": str(uuid.uuid4()),
        "created_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "collector": {"name": "compliance-artifact-collector", "version": __version__},
        "subject": subject,
        "scopes": scope_blocks,
        "artefacts": [{k: a[k] for k in ("id", "type", "title", "supports", "source", "data") if k in a} for a in artefacts],
    }
    if limitations:
        record["limitations"] = limitations
    jsonschema.validate(record, SCHEMA, format_checker=jsonschema.FormatChecker())
    return record, warnings


def push(record_path, url, key, opener=urllib.request.urlopen):
    """POST the record to Complear's conformity records API. Returns (status, response JSON)."""
    body = Path(record_path).read_bytes()
    request = urllib.request.Request(
        url.rstrip("/") + "/api/conformity-records/v1", data=body, method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                 "Content-Length": str(len(body)), "User-Agent": f"compliance-artifact-collector/{__version__}"})
    try:
        with opener(request, timeout=60) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def sign(record_path, key, transparency_log=False, run=_run, which=shutil.which):
    """Sign the written record with cosign sign-blob; the bundle sits next to it.

    Off by default, the public Sigstore transparency log would record the record's hash, the
    signature and the public key, which tells the world a provider signed a record at that time.
    """
    if not which("cosign"):
        raise RuntimeError("--sign-key needs cosign on PATH")
    bundle = f"{record_path}.bundle"
    tlog = [] if transparency_log else ["--tlog-upload=false"]
    result = run(["cosign", "sign-blob", "--yes", *tlog, "--key", str(key), "--bundle", bundle, str(record_path)])
    if result.returncode != 0:
        raise RuntimeError(f"cosign sign-blob failed: {result.stderr.strip()}")
    return bundle
