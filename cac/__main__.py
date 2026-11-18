import argparse
import json
import os
import sys
from pathlib import Path

import jsonschema

from cac import collect as c


def main(argv=None):
    p = argparse.ArgumentParser(prog="cac", description=c.__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)
    col = sub.add_parser("collect", help="build a conformity record from product.json")
    col.add_argument("config")
    col.add_argument("--out", required=True)
    col.add_argument("--sign-key", help="cosign private key; writes <out>.bundle")
    col.add_argument("--transparency-log", action="store_true",
                     help="also record the signature in the public Sigstore log (off by default)")
    val = sub.add_parser("validate", help="check a conformity record against the schema")
    val.add_argument("record")
    push = sub.add_parser("push", help="send a record to Complear (COMPLEAR_URL, COMPLEAR_UPLOAD_KEY)")
    push.add_argument("record")
    a = p.parse_args(argv)

    if a.command == "push":
        url, key = os.environ.get("COMPLEAR_URL"), os.environ.get("COMPLEAR_UPLOAD_KEY")
        if not url or not key:
            print("error: set COMPLEAR_URL and COMPLEAR_UPLOAD_KEY", file=sys.stderr)
            return 1
        status, body = c.push(a.record, url, key)
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0 if status == 200 else 1

    if a.command == "validate":
        try:
            jsonschema.validate(json.loads(Path(a.record).read_text()), c.SCHEMA, format_checker=jsonschema.FormatChecker())
        except jsonschema.ValidationError as exc:
            print(f"invalid: {exc.message}", file=sys.stderr)
            return 1
        print("valid")
        return 0

    config_path = Path(a.config)
    try:
        record, warnings = c.collect(json.loads(config_path.read_text()), base=config_path.parent)
    except (ValueError, KeyError, jsonschema.ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    scoped = ", ".join(f"{s['framework']['key']} {len(s['clauses'])} clauses" + (f" (tier {s['tier']})" if "tier" in s else "")
                       for s in record["scopes"])
    print(f"{out}: {len(record['artefacts'])} artefacts; {scoped}")
    if a.sign_key:
        try:
            print(f"signed: {c.sign(out, a.sign_key, a.transparency_log)}")
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
