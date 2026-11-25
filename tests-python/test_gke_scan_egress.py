"""RC-552: the bundle schema accepts gke-scan's fields, and egress_containment
covers Kubernetes.

The ticket's exit criteria:

* `verify_bundle` accepts the new attributes (`declared_ports`,
  `services_exposing_agent`) and Kubernetes `egress_containment` values, and
  still accepts existing Docker bundles (test_egress_containment.py and
  test_evidence_bundle.py, unchanged, and a Docker value here).
* Every case, each in a bundle that passes `verify_bundle`: no policy,
  allow-all, enforced and restrictive, unenforced; any address on TCP 443, as
  on the test bed; hostNetwork; and a forbidden enforcement check.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "tools" / "scan"
CENTRAL = SCAN / "gke" / "central_service"
FIXTURES = ROOT / "tests-python" / "fixtures" / "gke-scan"
sys.path.insert(0, str(SCAN))


def _load(name: str, path: Path):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


evidence = _load("evidence_bundle", SCAN / "evidence_bundle.py")
egress = _load("egress_containment", SCAN / "egress_containment.py")
fields = _load("gke_scan_pod_fields", CENTRAL / "pod_fields.py")
enforcement = _load("gke_scan_enforcement", CENTRAL / "enforcement.py")

B = {"answered": evidence._answered, "partial": evidence._partial,
     "blind": evidence._blind, "absent": evidence._absent}

ENFORCED = {"enforced": True, "by": "anetd", "detail": "GKE Dataplane V2: DaemonSet anetd in kube-system"}
UNENFORCED = {"enforced": False, "by": None, "detail": "no anetd or calico-node DaemonSet in kube-system"}
FORBIDDEN = {"enforced": None, "by": None, "detail": "gke-scan's role may not read DaemonSet anetd in kube-system"}

DNS = {"to": [{"namespaceSelector": {}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
       "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}
MCP = {"to": [{"podSelector": {"matchLabels": {"app": "finretail-mcp-server"}}}],
       "ports": [{"protocol": "TCP", "port": 23004}]}


def bundle(**attributes: dict[str, Any]) -> dict[str, Any]:
    """A v1 bundle as gke-scan will send it (RC-555 attaches authored_by)."""
    for attribute in attributes.values():
        if attribute["status"] in ("ANSWERED", "PARTIAL", "TEMPLATED"):
            attribute.setdefault("authored_by", "platform")
    return {
        "bundle_version": 1, "bundle_id": "bnd-0123456789ab", "host_id": "gke-test",
        "sandbox_name": "gke-test/agent-finretail", "collected_at": "2026-11-25T12:00:00+00:00",
        "rule_pack_version": evidence.RULE_PACK_VERSION,
        "inputs_attempted": {"runtime": {"attempted": True, "reached": True},
                             "image": {"attempted": False, "reason": "NOT_COLLECTED_BY_PACK"},
                             "manifest": {"attempted": True, "reached": True},
                             "repo": {"attempted": False, "reason": "NOT_COLLECTED_BY_PACK"}},
        "attestations": [],
        "attributes": attributes,
    }


def pod(labels: dict[str, str] | None = None, **spec: Any) -> dict[str, Any]:
    return {"metadata": {"name": "agent-finretail-58cd78b55d-48jcw", "namespace": "gke-test", "uid": "uid-1",
                         "labels": labels or {"app": "agent-finretail"}},
            "spec": {"containers": [{"name": "agent"}], **spec},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}}


def policy(name: str, egress_rules: list[Any] | None = None, selector: Any = None,
           types: list[str] | None = None) -> dict[str, Any]:
    spec: dict[str, Any] = {"podSelector": selector if selector is not None else {"matchLabels": {"app": "agent-finretail"}}}
    if types is not None:
        spec["policyTypes"] = types
    if egress_rules is not None:
        spec["egress"] = egress_rules
    return {"metadata": {"name": name, "namespace": "gke-test"}, "spec": spec}


class EgressCaseTest(unittest.TestCase):
    """Each case's level, status and value, in a bundle verify_bundle accepts."""

    def attribute(self, policies: list[dict[str, Any]], enforced: dict[str, Any], the_pod: dict[str, Any] | None = None):
        attribute = fields.egress_containment_attribute([the_pod or pod()], policies, enforced, B)
        self.assertEqual(evidence.contract_problems(bundle(egress_containment=copy.deepcopy(attribute))), [])
        evidence.verify_bundle(bundle(egress_containment=copy.deepcopy(attribute)))
        return attribute

    def test_no_policy_is_open(self):
        attribute = self.attribute([], ENFORCED)
        value = attribute["value"]
        self.assertEqual((attribute["status"], value["level"], value["contained"], value["enforcer"]),
                         ("ANSWERED", "open", False, None))
        self.assertEqual(value["reasons"], ["no NetworkPolicy of type Egress selects the pod"])
        self.assertEqual(value["observations"]["egress_policies"], [])

    def test_an_ingress_only_policy_doesnt_restrict_egress(self):
        value = self.attribute([policy("ingress-only", types=["Ingress"])], ENFORCED)["value"]
        self.assertEqual(value["level"], "open")

    def test_an_allow_all_policy_is_open(self):
        attribute = self.attribute([policy("restrict", [DNS], types=["Egress"]),
                                    policy("allow-all", [{}], types=["Ingress", "Egress"])], ENFORCED)
        self.assertEqual(attribute["value"]["level"], "open")
        self.assertEqual(attribute["value"]["reasons"], ["a policy allows all egress: allow-all"])

    def test_an_enforced_restrictive_policy_is_allow_list_enforced(self):
        attribute = self.attribute([policy("agent-egress", [DNS, MCP], types=["Egress"])], ENFORCED)
        value = attribute["value"]
        self.assertEqual((attribute["status"], value["level"], value["contained"], value["enforcer"]),
                         ("ANSWERED", "allow_list_enforced", True, "kubernetes_network_policy"))
        self.assertEqual(value["observations"]["egress_policies"], ["agent-egress"])
        self.assertEqual([a["ports"] for a in value["observations"]["allowed_egress"]], [DNS["ports"], MCP["ports"]])
        self.assertEqual(value["observations"]["open_to_any_address"], [])
        self.assertIn("enforced by anetd", value["reasons"])

    def test_policy_types_default_to_egress_when_rules_are_given(self):
        value = self.attribute([policy("no-types", [DNS])], ENFORCED)["value"]
        self.assertEqual(value["level"], "allow_list_enforced")

    def test_an_unenforced_restrictive_policy_is_open(self):
        value = self.attribute([policy("agent-egress", [DNS, MCP], types=["Egress"])], UNENFORCED)["value"]
        self.assertEqual(value["level"], "open")
        self.assertIn("the cluster doesn't enforce policies", value["reasons"][0])
        self.assertIs(value["observations"]["enforcement"]["enforced"], False)

    def test_any_address_on_tcp_443_as_on_the_test_bed(self):
        recorded = json.loads((FIXTURES / "gke-auto.json").read_text())["central_v3"]
        rules = recorded["network_policies_selecting_agent"][0]["egress"]
        attribute = self.attribute([policy("agent-finretail-egress", rules, types=["Egress"])], ENFORCED)
        value = attribute["value"]
        self.assertEqual((attribute["status"], value["level"]), ("ANSWERED", "open"))
        self.assertEqual(value["reasons"], ["a policy allows TCP 443 to any address"])
        self.assertEqual(value["observations"]["open_to_any_address"],
                         [{"policy": "agent-finretail-egress", "ports": [{"protocol": "TCP", "port": 443}],
                           "cidr": "0.0.0.0/0", "except": []}])
        self.assertEqual(len(value["observations"]["allowed_egress"]), 7)

    def test_an_except_list_doesnt_make_any_address_contained(self):
        rule = {"to": [{"ipBlock": {"cidr": "::/0", "except": ["fd00::/8"]}}], "ports": [{"port": 443}]}
        value = self.attribute([policy("v6", [rule], types=["Egress"])], ENFORCED)["value"]
        self.assertEqual(value["level"], "open")
        self.assertEqual(value["observations"]["open_to_any_address"][0]["except"], ["fd00::/8"])

    def test_a_slash_zero_with_host_bits_is_any_address(self):
        # Kubernetes masks an ipBlock's cidr, so 10.0.0.0/0 is 0.0.0.0/0 and
        # 2001:db8::/0 is ::/0; the cidr is kept as written.
        for cidr in ("10.0.0.0/0", "2001:db8::/0"):
            with self.subTest(cidr=cidr):
                rule = {"to": [{"ipBlock": {"cidr": cidr}}], "ports": [{"port": 443}]}
                attribute = self.attribute([policy("sloppy", [DNS, rule], types=["Egress"])], ENFORCED)
                value = attribute["value"]
                self.assertEqual((attribute["status"], value["level"], value["contained"]), ("ANSWERED", "open", False))
                self.assertEqual(value["observations"]["open_to_any_address"][0]["cidr"], cidr)

    def test_a_narrower_block_or_an_unparsable_cidr_isnt_any_address(self):
        for cidr in ("10.0.0.0/8", "0.0.0.0/1", "not-a-cidr"):
            with self.subTest(cidr=cidr):
                rule = {"to": [{"ipBlock": {"cidr": cidr}}], "ports": [{"port": 443}]}
                value = self.attribute([policy("narrow", [DNS, rule], types=["Egress"])], ENFORCED)["value"]
                self.assertEqual(value["level"], "allow_list_enforced")
                self.assertEqual(value["observations"]["open_to_any_address"], [])

    def test_a_rule_with_ports_and_no_peers_opens_those_ports_to_any_address(self):
        value = self.attribute([policy("https-anywhere", [DNS, {"ports": [{"port": 443}]}], types=["Egress"])],
                               ENFORCED)["value"]
        self.assertEqual(value["level"], "open")
        self.assertEqual(value["observations"]["open_to_any_address"][0]["cidr"], None)

    def test_host_network(self):
        attribute = self.attribute([policy("agent-egress", [DNS], types=["Egress"])], ENFORCED, pod(hostNetwork=True))
        value = attribute["value"]
        self.assertEqual((attribute["status"], value["level"], value["contained"]), ("ANSWERED", "host_network", False))
        self.assertTrue(value["observations"]["host_network"])

    def test_a_forbidden_enforcement_check_is_partial(self):
        attribute = self.attribute([policy("agent-egress", [DNS, MCP], types=["Egress"])], FORBIDDEN)
        value = attribute["value"]
        self.assertEqual((attribute["status"], attribute["reason"], value["level"], value["contained"]),
                         ("PARTIAL", "NO_SOURCE_ACCESS", "open", False))
        self.assertIsNone(value["observations"]["enforcement"]["enforced"])
        self.assertIn("couldn't be checked", attribute["note"])

    def test_with_no_restricting_policy_enforcement_doesnt_matter(self):
        attribute = self.attribute([], FORBIDDEN)
        self.assertEqual((attribute["status"], attribute["value"]["level"]), ("ANSWERED", "open"))

    def test_an_unevaluable_selector_is_partial_and_never_contained(self):
        odd = policy("odd", [{}], selector={"matchExpressions": [{"key": "app", "operator": "Gt", "values": ["1"]}]},
                     types=["Egress"])
        attribute = self.attribute([policy("agent-egress", [DNS], types=["Egress"]), odd], ENFORCED)
        self.assertEqual((attribute["status"], attribute["reason"]), ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual(attribute["value"]["level"], "open")
        self.assertEqual(attribute["value"]["observations"]["unevaluable_policies"], ["odd"])

    def test_long_rule_lists_are_cut_to_the_schemas_bound(self):
        rules = [{"to": [{"podSelector": {"matchLabels": {"app": f"svc-{i}"}}}], "ports": [{"port": 8000 + i}]}
                 for i in range(80)]
        value = self.attribute([policy("many", rules, types=["Egress"])], ENFORCED)["value"]
        self.assertEqual(len(value["observations"]["allowed_egress"]), egress.MAX_LIST)
        self.assertIn("16 more egress rule(s) not listed", value["reasons"])


class SchemaTest(unittest.TestCase):
    def test_a_docker_value_still_passes(self):
        inspect = {"Name": "/agent", "HostConfig": {"NetworkMode": "none"}, "Config": {"Labels": {}}}
        status, value = egress.classify(inspect, {"networks": {}})
        self.assertEqual((status, value["level"]), ("ANSWERED", "no_network"))
        attribute = evidence._answered(value, "observed", authored_by="none")
        self.assertEqual(evidence.contract_problems(bundle(egress_containment=attribute)), [])

    def test_a_kubernetes_value_with_dockers_keys_or_a_docker_value_without_them_fails(self):
        _, value = egress.classify_kubernetes(False, [], [], ENFORCED)
        mixed = copy.deepcopy(value)
        mixed["observations"]["privileged"] = False
        problems = evidence.contract_problems(bundle(egress_containment=evidence._answered(mixed, "observed",
                                                                                           authored_by="none")))
        self.assertTrue(any("privileged: not a field" in p for p in problems), problems)
        wrong_enforcer = copy.deepcopy(value)
        wrong_enforcer["enforcer"] = "calico"
        problems = evidence.contract_problems(bundle(egress_containment=evidence._answered(
            wrong_enforcer, "observed", authored_by="none")))
        self.assertTrue(any("enforcer" in p for p in problems), problems)

    def test_the_new_attributes_pass_and_bad_values_fail(self):
        recorded = json.loads((FIXTURES / "gke-test.json").read_text())
        gateway = {"metadata": {"name": "agent-finretail-gateway", "namespace": "gke-test"},
                   "spec": {"type": "ClusterIP", "selector": {"app": "agent-finretail"},
                            "ports": [{"name": "gateway", "port": 18789, "targetPort": 18789}]}}
        attributes = fields.pod_spec_attributes(recorded["pods"], [gateway], [], [], B, enforcement=ENFORCED)
        self.assertEqual(attributes["declared_ports"]["value"], [{"port": 18789, "protocol": "TCP"}])
        whole = bundle(**copy.deepcopy(attributes))
        self.assertEqual(evidence.contract_problems(whole), [])
        evidence.verify_bundle(whole)

        bad_port = bundle(declared_ports=evidence._answered([{"port": 70000, "protocol": "TCP"}], "declared",
                                                            authored_by="platform"))
        self.assertTrue(any("at most 65535" in p for p in evidence.contract_problems(bad_port)))
        bad_service = bundle(services_exposing_agent=evidence._answered(
            [{"name": "x", "type": "Ingress", "ports": []}], "declared", authored_by="platform"))
        self.assertTrue(any("type" in p for p in evidence.contract_problems(bad_service)))
        blind = bundle(declared_ports=evidence._blind("NO_SOURCE_ACCESS", "declared"))
        self.assertEqual(evidence.contract_problems(blind), [], "a BLIND value isn't held to the shape")

    def test_v2_holds_the_new_values_to_the_same_defs(self):
        bad = evidence._answered([{"port": 0, "protocol": "TCP"}], "declared", authored_by="platform")
        problems = evidence._semantic_problems_v2({"sandbox": {"attributes": {"declared_ports": bad}}, "agents": []})
        self.assertTrue(any("sandbox.attributes.declared_ports.value[0].port" in p for p in problems), problems)

    def test_lists_past_the_bound_are_cut_with_a_note(self):
        many = {"metadata": {"name": "p", "namespace": "agents"},
                "spec": {"containers": [{"name": "agent", "ports": [{"containerPort": 1000 + i} for i in range(70)]}]},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
        attribute = fields.declared_ports_attribute([many], B)
        self.assertEqual(len(attribute["value"]), fields.MAX_LIST)
        self.assertEqual(attribute["note"], "6 more port(s) not listed")
        self.assertEqual(evidence.contract_problems(bundle(declared_ports=attribute)), [])


class EnforcementCheckTest(unittest.TestCase):
    class Kube:
        def __init__(self, present=(), refuse=None, fail=None, status=None):
            self.present, self.refuse, self.fail, self.reads = set(present), refuse, fail, []
            self.status = status or {}

        def get_object(self, api_version, plural, namespace, name):
            self.reads.append((api_version, plural, namespace, name))
            if name == self.refuse:
                error = RuntimeError("HTTP 403")
                error.status = 403
                raise error
            if name == self.fail:
                raise RuntimeError("GET daemonsets: HTTP 500")
            if name not in self.present:
                return None
            daemonset = {"metadata": {"name": name}}
            status = self.status.get(name, {"desiredNumberScheduled": 3, "numberReady": 3})
            if status is not None:
                daemonset["status"] = status
            return daemonset

    def test_anetd_calico_or_neither(self):
        kube = self.Kube(present={"anetd"})
        self.assertEqual(enforcement.check(kube), ENFORCED)
        self.assertEqual(kube.reads, [("apps/v1", "daemonsets", "kube-system", "anetd")])
        self.assertEqual(enforcement.check(self.Kube(present={"calico-node"}))["by"], "calico-node")
        self.assertEqual(enforcement.check(self.Kube()), UNENFORCED)

    def test_a_refused_or_failed_read_is_unknown_not_unenforced(self):
        self.assertEqual(enforcement.check(self.Kube(refuse="anetd")), FORBIDDEN)
        failed = enforcement.check(self.Kube(fail="calico-node"))
        self.assertIsNone(failed["enforced"])
        self.assertIn("HTTP 500", failed["detail"])

    def test_an_enforcer_without_every_pod_ready_is_unknown_not_enforced(self):
        for status in ({"desiredNumberScheduled": 3, "numberReady": 2},
                       {"desiredNumberScheduled": 3, "numberReady": 0},
                       None):
            with self.subTest(status=status):
                answer = enforcement.check(self.Kube(present={"anetd"}, status={"anetd": status}))
                self.assertEqual((answer["enforced"], answer["by"]), (None, None))
                self.assertIn("anetd", answer["detail"])
        partly = enforcement.check(self.Kube(present={"anetd"},
                                             status={"anetd": {"desiredNumberScheduled": 3, "numberReady": 2}}))
        self.assertIn("2 of 3", partly["detail"])

    def test_an_enforcer_scheduled_on_no_node_doesnt_enforce(self):
        answer = enforcement.check(self.Kube(present={"calico-node"},
                                             status={"calico-node": {"desiredNumberScheduled": 0, "numberReady": 0}}))
        self.assertEqual((answer["enforced"], answer["by"]), (False, None))
        self.assertIn("calico-node", answer["detail"])

    def test_a_ready_enforcer_wins_over_one_that_isnt(self):
        answer = enforcement.check(self.Kube(present={"anetd", "calico-node"},
                                             status={"anetd": {"desiredNumberScheduled": 3, "numberReady": 1}}))
        self.assertEqual((answer["enforced"], answer["by"]), (True, "calico-node"))

    def test_a_restrictive_policy_with_an_enforcer_not_ready_is_partial_never_contained(self):
        answer = enforcement.check(self.Kube(present={"anetd"},
                                             status={"anetd": {"desiredNumberScheduled": 3, "numberReady": 2}}))
        attribute = fields.egress_containment_attribute([pod()], [policy("agent-egress", [DNS, MCP], types=["Egress"])],
                                                        answer, B)
        evidence.verify_bundle(bundle(egress_containment=copy.deepcopy(attribute)))
        self.assertEqual((attribute["status"], attribute["reason"], attribute["value"]["level"],
                          attribute["value"]["contained"]), ("PARTIAL", "NO_SOURCE_ACCESS", "open", False))

    def test_checked_once_per_interval_and_again_after_a_failure(self):
        now = [0.0]
        kube = self.Kube(present={"anetd"})
        check = enforcement.EnforcementCheck(kube, 3600, clock=lambda: now[0])
        self.assertTrue(check.current()["enforced"])
        now[0] = 1800
        check.current()
        self.assertEqual(len(kube.reads), 1)
        now[0] = 3600
        check.current()
        self.assertEqual(len(kube.reads), 2)
        flaky = self.Kube(refuse="anetd")
        retrying = enforcement.EnforcementCheck(flaky, 3600, clock=lambda: 0.0)
        self.assertIsNone(retrying.current()["enforced"])
        flaky.refuse, flaky.present = None, {"anetd"}
        self.assertTrue(retrying.current()["enforced"], "a failed check isn't kept for the interval")


if __name__ == "__main__":
    unittest.main()
