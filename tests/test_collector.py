import copy
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import jsonschema

from cac import collect as c
from cac.__main__ import main

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "nodesight"
CONFIG = json.loads((EXAMPLE / "product.json").read_text())


def AI(citation):
    return {"framework": "eu_ai_act", "citation": citation}


def done(code, stderr=""):
    return subprocess.CompletedProcess([], code, "", stderr)


class CollectorTest(unittest.TestCase):
    def collect(self, config=CONFIG, **kw):
        return c.collect(copy.deepcopy(config), base=EXAMPLE, **kw)

    def test_example_record_is_valid_and_scoped(self):
        record, _ = self.collect()
        [ai_act] = record["scopes"]
        self.assertEqual(ai_act["tier"], "high_risk_6_1")
        self.assertIn("Art.43(3)", ai_act["clauses"])
        self.assertNotIn("Art.43(1)", ai_act["clauses"])  # Annex III route only
        # The pack's own scoping answers, as Complear records them when the framework is applied.
        self.assertTrue(ai_act["answers"]["ai_act_category"].startswith("High-risk: product"))
        self.assertEqual([a["id"] for a in record["artefacts"]],
                         ["sbom-1", "signature-1", "evaluation-1", "certificate-1", "certificate-2"])

    def test_sbom_summary_and_dataset_rule(self):
        art = c.sbom_artefact("sbom.cdx.json", EXAMPLE)
        self.assertEqual(art["data"]["models"][0]["name"], "nodesight-unet")
        self.assertEqual(art["data"]["licenses"], ["BSD-3-Clause", "MIT", "Proprietary"])
        self.assertIn(AI("Art.10(2)"), art["supports"])
        self.assertEqual(art["source"]["sha256"], c.sha256(EXAMPLE / "sbom.cdx.json"))
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "s.json").write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"type": "library", "name": "x"}]}))
            self.assertNotIn(AI("Art.10(2)"), c.sbom_artefact("s.json", Path(d))["supports"])
            (Path(d) / "spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3"}))
            with self.assertRaises(ValueError):
                c.sbom_artefact("spdx.json", Path(d))

    def test_signature_states(self):
        image = {"ref": "r.example/x:1", "digest": "sha256:" + "a" * 64, "cosign": {"identity": "ci@x", "issuer": "https://issuer"}}
        calls = []
        ok = c.signature_artefact(image, EXAMPLE, run=lambda cmd: calls.append(cmd) or done(0), which=lambda _: "/bin/cosign")
        self.assertTrue(ok["data"]["verified"])
        self.assertEqual(calls[0][-1], "r.example/x@sha256:" + "a" * 64)  # verifies the digest, not the tag
        port = dict(image, ref="host:5000/team/x:1")
        c.signature_artefact(port, EXAMPLE, run=lambda cmd: calls.append(cmd) or done(0), which=lambda _: "/bin/cosign")
        self.assertEqual(calls[1][-1], "host:5000/team/x@sha256:" + "a" * 64)
        bad = c.signature_artefact(image, EXAMPLE, run=lambda cmd: done(1, "error: no matching signatures"), which=lambda _: "/bin/cosign")
        self.assertIs(bad["data"]["verified"], False)
        self.assertIn("no matching signatures", bad["data"]["detail"])
        missing = c.signature_artefact(image, EXAMPLE, which=lambda _: None)
        self.assertIsNone(missing["data"]["verified"])

    def test_failed_signature_is_warned(self):
        config = copy.deepcopy(CONFIG)
        config["image"]["cosign"] = {"key": "cosign.pub"}
        _, warnings = self.collect(config, run=lambda cmd: done(1, "bad"), which=lambda _: "/bin/cosign")
        self.assertTrue(any("failed verification" in w for w in warnings))

    def test_benchmark_scorecard_becomes_evaluation(self):
        art = c.evaluation_artefact("scorecard.json", ROOT / "tests" / "fixtures")
        self.assertEqual(art["data"]["name"], "Compliance Draft Benchmark")
        self.assertIn(AI("Art.15(3)"), art["supports"])
        self.assertEqual(len(art["data"]["metrics"]), 3)

    def test_reader_used_without_facts_and_flagged(self):
        config = copy.deepcopy(CONFIG)
        facts = config.pop("facts")
        record, _ = self.collect(config, read=lambda text: (facts, True))
        self.assertEqual(record["scopes"][0]["method"], "reader")
        self.assertTrue(record["limitations"])

    def test_bad_facts_and_unknown_clause(self):
        config = copy.deepcopy(CONFIG)
        config["facts"]["mdr_class"] = "IV"
        with self.assertRaises(ValueError):
            self.collect(config)
        config = copy.deepcopy(CONFIG)
        config["evaluations"][0]["supports"] = ["Art.99(1)"]
        _, warnings = self.collect(config)
        self.assertTrue(any("Art.99(1)" in w for w in warnings))

    def test_schema_rejects_malformed_artefact(self):
        record, _ = self.collect()
        record["artefacts"][1]["data"]["digest"] = "latest"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(record, c.SCHEMA)

    def test_signing_stays_off_the_public_log_by_default(self):
        calls = []
        c.sign("r.json", "k", run=lambda cmd: calls.append(cmd) or done(0), which=lambda _: "/bin/cosign")
        c.sign("r.json", "k", transparency_log=True, run=lambda cmd: calls.append(cmd) or done(0), which=lambda _: "/bin/cosign")
        self.assertIn("--tlog-upload=false", calls[0])
        self.assertNotIn("--tlog-upload=false", calls[1])

    def test_cli_writes_and_validates(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "record.json"
            self.assertEqual(main(["collect", str(EXAMPLE / "product.json"), "--out", str(out)]), 0)
            self.assertEqual(main(["validate", str(out)]), 0)

    def test_tags_name_their_framework(self):
        self.assertEqual(c.tags(["Art.15(3)", "iso42001:8.2", {"framework": "nist_ai_rmf", "citation": "MEASURE 2.5"}, "Art.15(3)"]),
                         [AI("Art.15(3)"), {"framework": "iso42001", "citation": "8.2"},
                          {"framework": "nist_ai_rmf", "citation": "MEASURE 2.5"}])

    def test_other_frameworks_are_supplied_scopes(self):
        config = copy.deepcopy(CONFIG)
        config["scopes"] = [{"framework": {"key": "iso42001", "version": "2023"}, "clauses": ["8.2", "9.1"]}]
        config["evaluations"][0]["supports"] = ["Art.15(3)", "iso42001:9.1", "nist_ai_rmf:MEASURE 2.5"]
        record, warnings = self.collect(config)
        self.assertEqual([(s["framework"]["key"], s["method"]) for s in record["scopes"]],
                         [("eu_ai_act", "facts_supplied"), ("iso42001", "supplied")])
        self.assertIn({"framework": "iso42001", "citation": "9.1"}, record["artefacts"][2]["supports"])
        self.assertEqual([w for w in warnings if "no scope" in w], ["evaluation-1 supports nist_ai_rmf, which no scope in this record covers"])
        with self.assertRaises(ValueError):
            self.collect(dict(config, frameworks=["iso42001"]))
        record, _ = self.collect(dict(config, frameworks=[]))
        self.assertEqual([s["framework"]["key"] for s in record["scopes"]], ["iso42001"])

    def test_an_ai_act_tag_must_be_an_ai_act_citation(self):
        record, _ = self.collect()
        record["artefacts"][0]["supports"] = [AI("clause 4")]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(record, c.SCHEMA)
        record["artefacts"][0]["supports"] = [{"framework": "iso42001", "citation": "clause 4"}]
        jsonschema.validate(record, c.SCHEMA)

    def test_test_reports_become_evaluations(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "r.xml").write_text('<testsuites><testsuite><testcase name="a"/><testcase name="b"><failure/></testcase>'
                                           '<testcase name="c"><skipped/></testcase><testcase name="d"/></testsuite></testsuites>')
            (Path(d) / "r.json").write_text(json.dumps({"results": {"summary": {"tests": 10, "passed": 9, "failed": 1, "skipped": 0}}}))
            junit = c.evaluation_artefact({"junit": "r.xml", "name": "Robustness", "supports": ["Art.15(4)"]}, Path(d))
            ctrf = c.evaluation_artefact({"ctrf": "r.json", "name": "Accuracy", "tool": "AITF"}, Path(d), lang="de")
        self.assertEqual(junit["data"]["tests"], {"total": 4, "failed": 1, "skipped": 1, "passed": 2})
        self.assertEqual(junit["data"]["metrics"], [{"name": "pass_rate", "value": 0.6667, "n": 3, "higher_is_better": True}])
        self.assertEqual(junit["title"], "Robustness: 2 of 4 tests passed")
        self.assertEqual(ctrf["title"], "Accuracy: 9 von 10 Tests bestanden")
        self.assertEqual(ctrf["data"]["tool"], "AITF")

    def test_ctrf_pending_and_other_are_not_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for passed, failed, pending, other in [(2, 1, 5, 1), (0, 0, 5, 4)]:
                with self.subTest(passed=passed):
                    summary = {"tests": 10, "passed": passed, "failed": failed,
                               "skipped": 1, "pending": pending, "other": other}
                    (base / "report.json").write_text(json.dumps({"results": {"summary": summary}}))
                    config = {"subject": CONFIG["subject"], "facts": CONFIG["facts"],
                              "evaluations": [{"ctrf": "report.json", "name": "CTRF"}]}
                    record, _ = c.collect(config, base)
                    data = record["artefacts"][0]["data"]
                    self.assertEqual(data["tests"], {"total": 10, "passed": passed, "failed": failed,
                                                     "skipped": 1 + pending + other})
                    expected = ([{"name": "pass_rate", "value": 0.6667, "n": 3,
                                  "higher_is_better": True}] if passed else [])
                    self.assertEqual(data["metrics"], expected)

    def test_scorecard_limitations_survive_collection(self):
        card = json.loads((ROOT / "tests/fixtures/scorecard.json").read_text())
        config = {"subject": CONFIG["subject"], "evaluations": ["scorecard.json"]}
        record, _ = c.collect(config, ROOT / "tests/fixtures", read=lambda _: (CONFIG["facts"], True))
        self.assertIn("Facts were extracted by a language model", record["limitations"][0])
        self.assertIn("evaluation-1: " + card["limitations"], record["limitations"])
        self.assertNotIn("limitations", record["artefacts"][0])

    def test_titles_follow_the_subject_language(self):
        config = copy.deepcopy(CONFIG)
        config["subject"]["language"] = "pt-PT"
        record, _ = self.collect(config)
        self.assertEqual(record["subject"]["language"], "pt-PT")
        self.assertTrue(record["artefacts"][0]["title"].startswith("SBOM (") and "componentes" in record["artefacts"][0]["title"])
        self.assertEqual(record["artefacts"][1]["title"], "Assinatura da imagem não verificada")
        config["subject"]["language"] = "sv"
        record, _ = self.collect(config)
        self.assertEqual(record["artefacts"][1]["title"], "Image signature not checked")

    def test_push_posts_the_record_with_the_key(self):
        sent = []

        class Response(io.BytesIO):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def opener(request, timeout):
            sent.append(request)
            return Response(b'{"recorded": 2}')

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "r.json").write_text('{"schema_version": "0.3"}')
            status, body = c.push(Path(d) / "r.json", "https://acme.complear.example/", "ck_live_x", opener=opener)
        self.assertEqual((status, body), (200, {"recorded": 2}))
        [request] = sent
        self.assertEqual(request.full_url, "https://acme.complear.example/api/conformity-records/v1")
        self.assertEqual(request.get_header("Authorization"), "Bearer ck_live_x")
        self.assertEqual(request.get_header("Content-length"), "25")

    def test_aitf_run_becomes_an_evaluation_with_its_provenance(self):
        aitf = ROOT / "examples" / "aitf"
        config = {"subject": CONFIG["subject"], "facts": CONFIG["facts"],
                  "evaluations": [{"aitf": "modules/compliance-draft-test-c8ngr694/module.json",
                                   "supports": ["Art.9(2)"]}]}
        record, _ = c.collect(copy.deepcopy(config), base=aitf)
        [art] = [a for a in record["artefacts"] if a["type"] == "evaluation"]
        data = art["data"]
        self.assertEqual(data["tool"][:6], "AITF: ")
        self.assertIn({"name": "clause_coverage", "value": 0.9203, "n": 79, "higher_is_better": True}, data["metrics"])
        self.assertIn(AI("Art.15(3)"), art["supports"])  # from the scorecard
        self.assertIn(AI("Art.9(2)"), art["supports"])  # from the item
        self.assertTrue(art["source"]["path"].startswith("evaluations/sha256:efb21540"))
        run = data["aitf"]
        self.assertEqual(run["execution"], "compliance-draft-test-c8ngr694")
        self.assertEqual(run["template"], "compliance-draft-test")
        self.assertEqual(run["state"], 1)
        self.assertEqual([s["name"] for s in run["steps"]], ["prepare", "predict", "evaluate"])
        self.assertIn({"name": "predictions", "output": True,
                       "payload_id": "sha256:93b59ccb6e64f2cf74edc4417316982cf73f687d81b02fdea0ba0b0f7dd343e8"},
                      run["artifacts"])
        self.assertEqual(set(run["modules"]), {"compliance-draft-dataset", "cdb-reader", "compliance-draft-evaluator"})

    def test_aitf_run_without_scorecard_takes_the_evaluation_metrics(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(ROOT / "examples" / "aitf", d, dirs_exist_ok=True)
            [card] = Path(d).glob("evaluations/*/scorecard.json")
            card.unlink()
            item = {"aitf": "modules/compliance-draft-test-c8ngr694/module.json"}
            art = c.evaluation_artefact(item, Path(d))
        self.assertEqual(art["data"]["tool"], "AITF")
        self.assertIn({"name": "Clause metrics: clause_coverage", "value": 0.9203}, art["data"]["metrics"])
        self.assertEqual(art["supports"], [])

    def test_aitf_refuses_a_location_outside_the_data_folder(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(ROOT / "examples" / "aitf", d, dirs_exist_ok=True)
            path = Path(d) / "modules/compliance-draft-test-c8ngr694/module.json"
            module = json.loads(path.read_text())
            [node] = [n for n in module["graph"]["nodes"] if n["node"] == "evaluation"]
            node["location"]["uri"] = "file:///data/../../etc/passwd"
            path.write_text(json.dumps(module))
            with self.assertRaisesRegex(ValueError, "leaves the data folder"):
                c.evaluation_artefact({"aitf": "modules/compliance-draft-test-c8ngr694/module.json"}, Path(d))

    def test_tai_scan_is_a_second_opinion(self):
        fields = {"role": "provider", "domain": "healthcare", "type": "medical device software",
                  "input_data": "chest CT", "intended_use": "detects lung nodules"}
        agree = {**CONFIG, "tai_scan": {**fields, "answer": {"level": " High-risk", "articles": "6, 9, Annex I, 43",
                                                              "annexes": "['VIII', 'III', 'VIII']"}}}
        record, _ = self.collect(agree)
        art = record["artefacts"][-1]
        self.assertEqual(art["id"], "classification-1")
        self.assertEqual(art["data"]["tier"], "high_risk")
        self.assertEqual(art["data"]["articles"], ["6", "9", "43"])
        self.assertEqual((art["data"]["level"], art["data"]["annexes"]), ("High-risk", "VIII, III"))
        self.assertTrue(art["data"]["agrees"])
        self.assertTrue(all(t["citation"].startswith("Art.6(") for t in art["supports"]))
        self.assertNotIn("TAI Scan", " ".join(record.get("limitations", [])))

        disagree = {**CONFIG, "tai_scan": {**fields, "answer": {"level": "Minimal risk"}}}
        record, _ = self.collect(disagree)
        self.assertFalse(record["artefacts"][-1]["data"]["agrees"])
        self.assertIn("classification-1: TAI Scan reads the risk level as minimal, the engine as high_risk",
                      " ".join(record["limitations"]))

    def test_tai_scan_calls_the_api_without_a_saved_answer(self):
        class Client:
            def __init__(self):
                self.calls = []

            def call(self, endpoint, features):
                self.calls.append(endpoint)
                return {"risk_level": {"level": "Limited risk"}, "relevant_resources": {"articles": "50"}}[endpoint]

        client = Client()
        item = {"role": "provider", "domain": "d", "type": "t", "input_data": "i", "intended_use": "u"}
        art = c.classification_artefact(item, [], client=client)
        self.assertEqual(client.calls, ["risk_level", "relevant_resources"])
        self.assertEqual((art["data"]["tier"], art["data"]["articles"]), ("limited", ["50"]))
        self.assertNotIn("agrees", art["data"])  # no EU AI Act scope to compare with
        with mock.patch.dict("os.environ", {"TAI_USER": "", "TAI_PASS": ""}):
            with self.assertRaisesRegex(ValueError, "TAI_USER"):
                c.classification_artefact(item, [])

    def test_committed_example_record_is_valid(self):
        jsonschema.validate(json.loads((EXAMPLE / "record.json").read_text()), c.SCHEMA,
                            format_checker=jsonschema.FormatChecker())

    def test_inline_evaluation_carries_its_file_and_result(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "check.json").write_text('{"result": "fail"}')
            art = c.evaluation_artefact({"tool": "Checklist", "name": "Pen test", "result": "fail", "file": "check.json",
                                         "supports": ["iso42001:9.1"]}, Path(d))
            unsure = c.evaluation_artefact({"tool": "Checklist", "name": "Scan", "result": "inconclusive"}, Path(d))
        self.assertEqual(art["source"], {"path": "check.json", "sha256": c.hashlib.sha256(b'{"result": "fail"}').hexdigest()})
        self.assertEqual(art["data"]["tests"], {"total": 1, "passed": 0, "failed": 1, "skipped": 0})
        self.assertEqual(art["title"], "Checklist: Pen test: 0 of 1 tests passed")
        self.assertEqual(unsure["data"]["tests"]["skipped"], 1)
        self.assertNotIn("source", unsure)

    def test_collect_without_the_ai_act_needs_no_benchmark(self):
        # A fresh interpreter in which importing the benchmark (cdb) fails.
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "check.json").write_text('{"result": "pass"}')
            (Path(d) / "product.json").write_text(json.dumps({
                "subject": {"name": "S", "version": "1", "provider": "P"}, "frameworks": [],
                "scopes": [{"framework": {"key": "iso42001", "version": "2023"}, "clauses": ["9.1"]}],
                "evaluations": [{"tool": "T", "name": "N", "result": "pass", "file": "check.json",
                                 "supports": ["iso42001:9.1"]}]}))
            run = subprocess.run(
                [sys.executable, "-c", "import sys; sys.modules['cdb'] = None; from cac.__main__ import main; "
                 f"sys.exit(main(['collect', {str(Path(d) / 'product.json')!r}, '--out', {str(Path(d) / 'r.json')!r}]))"],
                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)

if __name__ == "__main__":
    unittest.main()
