"""Write a product.json from the evidence folders of the AI Coding Tool Validation Kit.

    python examples/ai-tool-validation/kit_product.py evidence/CLAUDE evidence/GEN \\
        --name "Claude Code" --version 2.1 --provider Anthropic --profile lite --out product.json
    python -m cac collect product.json --out record.json
    python -m cac push record.json

The kit (https://github.com/bernardopersonal/ai-coding-tool-validation-kit) files each test's
evidence under <TEST-ID>/, as JSON with a top-level "result" (pass, fail or inconclusive) and
"generated_at_utc". Each such file becomes one evaluation, hashed, tagged with its test id in
Complear's ai_coding_tool_validation pack. Files without a "result" (a Markdown twin, a .sha256)
are not evidence of an outcome and are left out.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

FRAMEWORK = {"key": "ai_coding_tool_validation", "version": "2026.1"}
TEST_ID = re.compile(r"^(IQ|OQ|MA|RV|PQ)-\d\d$")
# The tests each profile runs (the kit's docs/lite-vs-full.md); context tests (OQ-20, OQ-30,
# OQ-40, RV-01) are added by the scope's answers in Complear, not assumed here.
LITE = ["IQ-03", "OQ-01", "OQ-02", "OQ-03", "OQ-04", "OQ-05", "OQ-06", "OQ-07", "OQ-08", "OQ-09",
        "OQ-10", "MA-01", "PQ-01", "PQ-02"]
FULL = sorted(LITE + ["IQ-01", "IQ-02", "IQ-04", "IQ-05", "OQ-11", "OQ-12", "OQ-13"])


def evaluations(evidence_dirs, base):
    """One inline evaluation per kit evidence JSON under <dir>/<TEST-ID>/, in test id then path order."""
    found = []
    for directory in evidence_dirs:
        for path in sorted(Path(directory).glob("*/**/*.json")):
            test_id = path.relative_to(directory).parts[0]
            if not TEST_ID.match(test_id):
                continue
            doc = json.loads(path.read_text())
            if not isinstance(doc, dict) or "result" not in doc:
                continue
            entry = {"tool": "AI Coding Tool Validation Kit", "name": f"{test_id} {path.stem}",
                     "result": doc["result"], "file": os.path.relpath(path, base),
                     "supports": [f"{FRAMEWORK['key']}:{test_id}"]}
            if isinstance(doc.get("generated_at_utc"), str):
                entry["date"] = doc["generated_at_utc"][:10]
            found.append((test_id, entry))
    return [entry for _, entry in sorted(found, key=lambda pair: pair[0])]


def product(evidence_dirs, base, name, version, provider, profile):
    return {
        "subject": {"name": name, "version": version, "provider": provider,
                    "intended_purpose": "AI coding tool validated as QMS and development software (ISO 13485:2016 4.1.6)"},
        "frameworks": [],
        "scopes": [{"framework": FRAMEWORK, "answers": {"validation_profile": profile.capitalize()},
                    "clauses": LITE if profile == "lite" else FULL}],
        "evaluations": evaluations(evidence_dirs, base),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("evidence", nargs="+", help="kit evidence folders, e.g. evidence/CLAUDE evidence/GEN")
    p.add_argument("--name", required=True, help="the tool, e.g. Claude Code")
    p.add_argument("--version", required=True, help="the validated tool version")
    p.add_argument("--provider", required=True, help="the vendor, e.g. Anthropic")
    p.add_argument("--profile", choices=["lite", "full"], required=True)
    p.add_argument("--out", required=True, help="product.json to write; evidence paths are relative to it")
    a = p.parse_args(argv)
    out = Path(a.out)
    config = product(a.evidence, out.resolve().parent, a.name, a.version, a.provider, a.profile)
    if not config["evaluations"]:
        print("error: no kit evidence (JSON with a \"result\") under <TEST-ID>/ in the given folders", file=sys.stderr)
        return 1
    out.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n")
    print(f"{out}: {len(config['evaluations'])} evaluations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
