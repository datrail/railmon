"""Egress containment (DR-207): the level read from Docker's view of a container.

The design is railxia/docs `design/2026-10-11-egress-containment`; its §6 lists the cases
below. The inspect shapes are Docker's own: an OpenShell 0.1.3 sandbox as its Docker driver
creates one (`network_mode=none`, its fixed labels), a Compose service, and the variants that
make a network setting meaningless.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "tools" / "scan"


def _load(name: str):
    """A private copy, not registered: discovery imports every test file
    before any runs, and the other files register their own copies under
    these names (`sys.modules.setdefault`). Ours go in only while this
    file's tests run (`setUpModule`)."""
    spec = importlib.util.spec_from_file_location(name, SCANNER_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scanner = _load("scan_agent_environment")
evidence_bundle = _load("evidence_bundle")
egress = _load("egress_containment")
composer = _load("compose_evidence_bundle_v2")
_modules = mock.patch.dict(sys.modules, {
    "scan_agent_environment": scanner,
    "evidence_bundle": evidence_bundle,
    "egress_containment": egress,
})


def setUpModule():
    _modules.start()


def tearDownModule():
    _modules.stop()


OPENSHELL_LABELS = {
    "openshell.ai/managed-by": "openshell",
    "openshell.ai/isolation-backend": "openshell-sandbox",
    "openshell.ai/isolation-role": "sandbox",
    "openshell.ai/sandbox-name": "my-agent",
}


def container(mode="bridge", networks=("bridge",), labels=None, mounts=(), privileged=False,
              name="agent", cid="c-agent"):
    return {
        "Id": cid,
        "Name": "/" + name,
        "Config": {"Labels": dict(labels or {})},
        "HostConfig": {"NetworkMode": mode, "Privileged": privileged, "CapDrop": ["ALL"]},
        "NetworkSettings": {"Networks": {n: {} for n in networks}},
        "Mounts": [dict(m) for m in mounts],
    }


def bind(source, target=None):
    return {"Type": "bind", "Source": source, "Destination": target or source}


OPENSHELL = container("none", ("none",), OPENSHELL_LABELS, name="openshell-my-agent-1a2b")


class Docker:
    """A fake Docker: containers and networks by id or name; anything else is
    a failed inspect (None)."""

    def __init__(self, containers=(), networks=None):
        self.containers = {}
        for c in containers:
            self.containers[c["Id"]] = c
            self.containers[c["Name"].lstrip("/")] = c
        self.networks = networks or {}

    def container(self, ref):
        return copy.deepcopy(self.containers.get(ref))

    def network(self, ref):
        return copy.deepcopy(self.networks.get(ref))


def net(internal, *members):
    return {"Internal": internal, "Containers": {m["Id"]: {"Name": m["Name"].lstrip("/")} for m in members}}


def classify(target, docker=None, extra=()):
    docker = docker or Docker([target], {"bridge": net(False, target)})
    inputs = egress.collect_inputs(target, docker.container, docker.network)
    return egress.classify(target, inputs, extra)


class LevelTest(unittest.TestCase):
    def assertLevel(self, result, level, status="ANSWERED"):
        got_status, value = result
        self.assertEqual(got_status, status)
        self.assertEqual(value["level"], level)
        self.assertEqual(value["contained"], level in ("allow_list_enforced", "no_network", "internal_network"))
        return value

    def test_an_openshell_sandbox_has_an_enforced_allow_list(self):
        value = self.assertLevel(classify(OPENSHELL, Docker([OPENSHELL])), "allow_list_enforced")
        self.assertEqual(value["enforcer"], "openshell")
        self.assertIsNone(value["allow_list"])
        self.assertTrue(value["observations"]["openshell_labels"])
        # Docker's `none` entry is not an attached network.
        self.assertEqual(value["observations"]["networks"], [])

    def test_the_compose_demo_on_its_bridge_is_open(self):
        agent = container("datrail_default", ("datrail_default",))
        docker = Docker([agent], {"datrail_default": net(False, agent)})
        value = self.assertLevel(classify(agent, docker), "open")
        self.assertEqual(value["observations"]["networks"],
                         [{"name": "datrail_default", "internal": False, "gateway_peers": []}])

    def test_network_none_without_openshell_is_no_network(self):
        agent = container("none", ("none",))
        self.assertLevel(classify(agent, Docker([agent])), "no_network")

    def test_openshell_labels_on_an_open_container_raise_nothing(self):
        agent = container("bridge", ("bridge",), OPENSHELL_LABELS)
        self.assertLevel(classify(agent), "open")

    def test_host_network(self):
        agent = container("host", ("host",))
        self.assertLevel(classify(agent, Docker([agent], {"host": net(False)})), "host_network")

    def test_an_internal_network_with_a_proxy_on_it_names_the_proxy(self):
        agent = container("private", ("private",))
        squid = container("private", ("private", "outside"), name="squid", cid="c-squid")
        quiet = container("private", ("private",), name="db", cid="c-db")
        docker = Docker([agent, squid, quiet], {
            "private": net(True, agent, squid, quiet),
            "outside": net(False, squid),
        })
        value = self.assertLevel(classify(agent, docker), "internal_network")
        self.assertEqual(value["observations"]["networks"][0]["gateway_peers"], ["squid"])
        self.assertIn("reaches outside only through: squid", value["reasons"])

    def test_an_internal_network_alone_has_no_gateway(self):
        agent = container("private", ("private",))
        value = self.assertLevel(classify(agent, Docker([agent], {"private": net(True, agent)})),
                                 "internal_network")
        self.assertEqual(value["observations"]["networks"][0]["gateway_peers"], [])

    def test_internal_plus_a_bridge_is_open(self):
        agent = container("private", ("private", "bridge"))
        docker = Docker([agent], {"private": net(True, agent), "bridge": net(False, agent)})
        self.assertLevel(classify(agent, docker), "open")

    def test_a_mode_with_no_attached_network_is_never_contained(self):
        agent = container("private", ())
        self.assertLevel(classify(agent, Docker([agent])), "open")

    def test_a_missing_network_mode_is_failed(self):
        agent = container()
        del agent["HostConfig"]["NetworkMode"]
        self.assertEqual(classify(agent), ("FAILED", None))


class DowngradeTest(unittest.TestCase):
    def test_every_runtime_socket_by_file_or_directory_opens_an_openshell_sandbox(self):
        for source in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
                       "/var/run/containerd", "/run/k3s/containerd/containerd.sock", "/run/podman",
                       "/var/run/crio/crio.sock", "/run/user/1000/docker.sock", "/run/user/1000",
                       "/run/user", "/run", "/var/run", "/var", "/"):
            with self.subTest(source=source):
                sandbox = copy.deepcopy(OPENSHELL)
                sandbox["Mounts"] = [bind(source, "/host" + source.rstrip("/"))]
                status, value = classify(sandbox, Docker([sandbox]))
                self.assertEqual((status, value["level"], value["contained"]), ("ANSWERED", "open", False))
                self.assertTrue(value["observations"]["runtime_socket_mounts"])

    def test_a_socket_named_only_at_the_target_counts(self):
        sandbox = copy.deepcopy(OPENSHELL)
        sandbox["Mounts"] = [bind("/srv/odd/path", "/var/run/docker.sock")]
        self.assertEqual(classify(sandbox, Docker([sandbox]))[1]["level"], "open")

    def test_the_socket_this_scan_uses_counts(self):
        sandbox = copy.deepcopy(OPENSHELL)
        sandbox["Mounts"] = [bind("/srv/docker", "/d")]
        self.assertEqual(classify(sandbox, Docker([sandbox]))[1]["level"], "allow_list_enforced")
        self.assertEqual(classify(sandbox, Docker([sandbox]), ("/srv/docker/api.sock",))[1]["level"], "open")

    def test_ordinary_mounts_and_volumes_are_not_downgrades(self):
        sandbox = copy.deepcopy(OPENSHELL)
        sandbox["Mounts"] = [bind("/home/me/work", "/sandbox"),
                             {"Type": "volume", "Source": "/var/lib/docker/volumes/v/_data", "Destination": "/data"}]
        self.assertEqual(classify(sandbox, Docker([sandbox]))[1]["level"], "allow_list_enforced")

    def test_privileged_opens_no_network(self):
        agent = container("none", ("none",), privileged=True)
        status, value = classify(agent, Docker([agent]))
        self.assertEqual(value["level"], "open")
        self.assertTrue(value["observations"]["privileged"])
        self.assertIn("privileged container", value["reasons"])


class SharedNamespaceTest(unittest.TestCase):
    def test_the_owner_decides_the_network(self):
        owner = container("none", ("none",), OPENSHELL_LABELS, name="sandbox", cid="c-owner")
        agent = container("container:c-owner", ())
        status, value = classify(agent, Docker([agent, owner]))
        self.assertEqual((status, value["level"], value["via"]), ("ANSWERED", "allow_list_enforced", "container:sandbox"))

    def test_a_downgrade_on_either_side_counts(self):
        owner = container("none", ("none",), name="sandbox", cid="c-owner", privileged=True)
        agent = container("container:c-owner", ())
        self.assertEqual(classify(agent, Docker([agent, owner]))[1]["level"], "open")
        owner = container("none", ("none",), name="sandbox", cid="c-owner")
        agent = container("container:c-owner", (), mounts=[bind("/var/run/docker.sock")])
        self.assertEqual(classify(agent, Docker([agent, owner]))[1]["level"], "open")

    def test_an_owner_that_cannot_be_inspected_is_failed(self):
        agent = container("container:gone", ())
        self.assertEqual(classify(agent, Docker([agent])), ("FAILED", None))


class UninspectedNetworkTest(unittest.TestCase):
    def test_when_it_decides_the_answer_it_is_partial_open(self):
        agent = container("private", ("private",))
        status, value = classify(agent, Docker([agent], {}))
        self.assertEqual((status, value["level"], value["contained"]), ("PARTIAL", "open", False))
        self.assertIsNone(value["observations"]["networks"][0]["internal"])

    def test_when_another_network_is_open_it_is_a_plain_open(self):
        agent = container("private", ("private", "bridge"))
        status, value = classify(agent, Docker([agent], {"bridge": net(False, agent)}))
        self.assertEqual((status, value["level"]), ("ANSWERED", "open"))


class BoundsTest(unittest.TestCase):
    """A real topology never makes the value break the schema: a bundle past
    a bound would not be delivered at all (rail-review, 75)."""

    def test_a_crowded_internal_network_stays_inside_the_schema(self):
        agent = container("private", ("private",))
        peers = [container("private", ("private", "outside"), name="relay-" + "x" * 200 + str(i), cid=f"c-{i:03}")
                 for i in range(150)]
        docker = Docker([agent, *peers], {"private": net(True, agent, *peers), "outside": net(False, *peers)})
        calls = []
        inspect = docker.container
        docker.container = lambda ref: calls.append(ref) or inspect(ref)
        status, value = classify(agent, docker)
        self.assertEqual((status, value["level"]), ("ANSWERED", "internal_network"))
        self.assertLessEqual(len(calls), egress.PEER_INSPECT_BUDGET)
        self.assertLessEqual(len(value["observations"]["networks"][0]["gateway_peers"]), egress.MAX_LIST)
        self.assertTrue(all(len(r) <= egress.MAX_REASON for r in value["reasons"]))
        self.assertTrue(any("not checked" in r for r in value["reasons"]))
        schema = evidence_bundle.EGRESS_VALUE_SCHEMA
        self.assertEqual(evidence_bundle._schema_problems(value, schema, "value"), [])

    def test_many_networks_stay_inside_the_schema(self):
        names = [f"net-{i:03}" for i in range(80)]
        agent = container("net-000", names)
        docker = Docker([agent], {n: net(True, agent) for n in names})
        status, value = classify(agent, docker)
        self.assertEqual(value["level"], "internal_network")
        self.assertEqual(evidence_bundle._schema_problems(value, evidence_bundle.EGRESS_VALUE_SCHEMA, "value"), [])

    def test_the_default_bridge_is_open_even_when_it_cannot_be_inspected(self):
        agent = container("bridge", ("bridge",))
        self.assertEqual(classify(agent, Docker([agent], {}))[0:1], ("ANSWERED",))
        self.assertEqual(classify(agent, Docker([agent], {}))[1]["level"], "open")


class ProxyTest(unittest.TestCase):
    def test_proxy_urls_lose_their_credentials_and_no_proxy_is_kept(self):
        env = {"https_proxy": "http://user:secret@proxy.corp:3128/?token=x", "NO_PROXY": "localhost,.corp"}
        found = egress.declared_proxy(env, scanner.redact_url)
        self.assertEqual(found["NO_PROXY"], "localhost,.corp")
        self.assertNotIn("secret", found["HTTPS_PROXY"])
        self.assertNotIn("token", found["HTTPS_PROXY"])
        self.assertIn("proxy.corp", found["HTTPS_PROXY"])

    def test_no_proxy_variables_is_none(self):
        self.assertIsNone(egress.declared_proxy({"PATH": "/bin"}, scanner.redact_url))


def build_args():
    from argparse import Namespace

    return Namespace(config_path=[], mcp_config=[], evidence_bundle_output=None, compact=False)


def identity():
    return {
        "host_id": "h-1", "host_id_source": "container_env", "sandbox_name": "agent",
        "sandbox_name_source": "container_name", "mcp_servers": [], "observed_reach": {},
    }


class BundleTest(unittest.TestCase):
    """The two attributes as the v1 builder emits them, against the published schema."""

    def build(self, context):
        base = {
            "env": {}, "hostname": "h", "image": "sha256:deadbeef", "container_name": "agent",
            "container_id": "c-agent", "proc1_cmdline": "",
        }
        base.update(context)
        bundle = evidence_bundle.build_evidence_bundle(
            build_args(), base, {"host_id": "h-1", "sandbox_name": "agent"}, identity(),
        )
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])
        self.assertEqual(bundle["rule_pack_version"], 14)
        return bundle["attributes"]

    def docker(self, target, docker, env=None):
        return self.build({
            "mode": "docker", "docker_inspect": target, "env": env or {},
            "egress_inputs": egress.collect_inputs(target, docker.container, docker.network),
        })

    def test_an_openshell_sandbox_is_answered_observed(self):
        attr = self.docker(OPENSHELL, Docker([OPENSHELL]))["egress_containment"]
        self.assertEqual((attr["status"], attr["tier"], attr["authored_by"]), ("ANSWERED", "observed", "none"))
        self.assertEqual(attr["value"]["level"], "allow_list_enforced")

    def test_partial_and_failed_pass_the_contract(self):
        agent = container("private", ("private",))
        attr = self.docker(agent, Docker([agent], {}))["egress_containment"]
        self.assertEqual((attr["status"], attr["value"]["level"]), ("PARTIAL", "open"))
        agent = container("container:gone", ())
        attr = self.docker(agent, Docker([agent]))["egress_containment"]
        self.assertEqual((attr["status"], attr["value"]), ("FAILED", None))

    def test_a_declared_proxy_is_its_own_declared_attribute(self):
        agent = container("datrail_default", ("datrail_default",))
        attrs = self.docker(agent, Docker([agent], {"datrail_default": net(False, agent)}),
                            env={"HTTPS_PROXY": "http://u:p@proxy:3128"})
        self.assertEqual(attrs["egress_containment"]["value"]["level"], "open")
        proxy = attrs["egress_proxy_declared"]
        self.assertEqual((proxy["status"], proxy["tier"]), ("ANSWERED", "declared"))
        self.assertNotIn("u:p", proxy["value"]["HTTPS_PROXY"])

    def test_without_a_proxy_it_is_absent(self):
        attrs = self.docker(OPENSHELL, Docker([OPENSHELL]))
        self.assertEqual(attrs["egress_proxy_declared"]["status"], "ABSENT")

    def test_a_host_process_and_a_process_in_a_container(self):
        with mock.patch.object(scanner, "in_container", return_value=False):
            attr = self.build({"mode": "self", "docker_inspect": None})["egress_containment"]
        self.assertEqual((attr["status"], attr["value"]["level"]), ("ANSWERED", "host_process"))
        with mock.patch.object(scanner, "in_container", return_value=True):
            attr = self.build({"mode": "self", "docker_inspect": None})["egress_containment"]
        self.assertEqual((attr["status"], attr["reason"]), ("BLIND", "NO_SOURCE_ACCESS"))
        # Kubernetes on cgroup v2: in_container() can't tell, the environment can.
        with mock.patch.object(scanner, "in_container", return_value=False):
            attr = self.build({"mode": "self", "docker_inspect": None,
                               "env": {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}})["egress_containment"]
        self.assertEqual(attr["status"], "BLIND")

    def test_a_docker_context_without_inputs_is_blind(self):
        attr = self.build({"mode": "docker", "docker_inspect": OPENSHELL})["egress_containment"]
        self.assertEqual((attr["status"], attr["reason"]), ("BLIND", "NOT_COLLECTED_BY_PACK"))

    def test_the_schema_refuses_an_unknown_level_or_key(self):
        attrs = self.docker(OPENSHELL, Docker([OPENSHELL]))
        bundle = {"attributes": {"egress_containment": attrs["egress_containment"]}}
        schema = evidence_bundle.SCHEMA["properties"]["attributes"]
        bad = copy.deepcopy(bundle)
        bad["attributes"]["egress_containment"]["value"]["level"] = "mostly_contained"
        self.assertTrue(evidence_bundle._schema_problems(bad["attributes"], schema, "attributes"))
        bad = copy.deepcopy(bundle)
        bad["attributes"]["egress_containment"]["value"]["allow_list"] = ["api.github.com"]
        self.assertTrue(evidence_bundle._schema_problems(bad["attributes"], schema, "attributes"))
        bad = copy.deepcopy(bundle)
        bad["attributes"]["egress_containment"]["value"]["extra"] = 1
        self.assertTrue(evidence_bundle._schema_problems(bad["attributes"], schema, "attributes"))
        for field, wrong in (("via", {"x": 1}), ("via", 5)):
            bad = copy.deepcopy(bundle)
            bad["attributes"]["egress_containment"]["value"][field] = wrong
            self.assertTrue(evidence_bundle._schema_problems(bad["attributes"], schema, "attributes"), field)
        bad = copy.deepcopy(bundle)
        bad["attributes"]["egress_containment"]["value"]["observations"]["network_mode"] = ["none"]
        self.assertTrue(evidence_bundle._schema_problems(bad["attributes"], schema, "attributes"))
        # null is one of the listed types.
        ok = copy.deepcopy(bundle)
        ok["attributes"]["egress_containment"]["value"]["observations"]["network_mode"] = None
        self.assertEqual(evidence_bundle._schema_problems(ok["attributes"], schema, "attributes"), [])


class V2Test(unittest.TestCase):
    def test_both_attributes_are_sandbox_scoped(self):
        self.assertLessEqual({"egress_containment", "egress_proxy_declared"}, composer.SANDBOX_ATTRIBUTES)

    def test_the_v2_check_holds_the_sandbox_value_to_the_v1_shape(self):
        status, value = classify(OPENSHELL, Docker([OPENSHELL]))
        bundle = {
            "sandbox": {"attributes": {"egress_containment": {"status": "ANSWERED", "value": dict(value, level="nope")}}},
            "agents": [],
        }
        problems = evidence_bundle._semantic_problems_v2(bundle)
        self.assertTrue(any("egress_containment" in p for p in problems), problems)



class AllowListTest(unittest.TestCase):
    """DR-266: the sandbox's allow-list, read from OpenShell by `railmon
    openshell` (Daniel, 2026-10-28), never from RailDash's record."""

    NOW = 1_800_000_000.0

    def view(self):
        import json

        sys.path.insert(0, str(ROOT / "tools" / "openshell"))
        try:
            import collector
        finally:
            sys.path.pop(0)
        raw = json.loads((ROOT / "tests" / "fixtures" / "openshell-0.1.3" / "policy-full.json").read_text())
        return collector.strip_policy(raw)

    def body(self, sandbox="my-agent", age=30.0, every=60):
        from datetime import datetime, timezone

        read_at = datetime.fromtimestamp(self.NOW - age, timezone.utc).isoformat().replace("+00:00", "Z")
        return {"kind": "openshell_policy", "sandbox": sandbox, "read_at": read_at, "every": every,
                "view": self.view()}

    def classify_with(self, target, body):
        docker = Docker([target])
        inputs = egress.collect_inputs(target, docker.container, docker.network)
        inputs.update(openshell_policy=body, now=self.NOW)
        return egress.classify(target, inputs)

    def test_a_current_copy_for_this_sandbox_is_the_allow_list(self):
        status, value = self.classify_with(OPENSHELL, self.body())
        self.assertEqual((status, value["level"]), ("ANSWERED", "allow_list_enforced"))
        self.assertEqual([(e["host"], e["port"]) for e in value["allow_list"]], [
            ("*.example.com", 443), ("*.example.com", 8443), ("api.github.com", 443),
            ("raw.githubusercontent.com", 443), ("uploads.github.com", 443)])
        uploads = value["allow_list"][-1]
        self.assertEqual(uploads, {
            "host": "uploads.github.com", "port": 443, "protocol": "rest", "enforcement": "enforce",
            "access": None, "rules": [{"method": "GET", "path": "/repos/**"},
                                      {"method": "POST", "path": "/repos/*/*/releases/*/assets"}],
            "binaries": ["/usr/local/bin/python3.13"]})
        self.assertIn("allow-list: OpenShell's loaded policy revision 1, read by railmon openshell", value["reasons"])

    def test_the_same_policy_reads_the_same_on_every_scan(self):
        first = self.classify_with(OPENSHELL, self.body(age=10))
        later = self.classify_with(OPENSHELL, self.body(age=100))
        self.assertEqual(first, later)

    def test_no_copy_says_what_it_said_before(self):
        before = classify(OPENSHELL, Docker([OPENSHELL]))
        self.assertEqual(self.classify_with(OPENSHELL, None), before)
        self.assertIsNone(before[1]["allow_list"])

    def test_a_stale_copy_or_another_sandbox_is_not_read(self):
        for body, words in ((self.body(age=60 * 3 + 61), "is not current"),
                            (self.body(age=-120), "is not current"),
                            ({**self.body(), "read_at": "yesterday"}, "is not current"),
                            (self.body(sandbox="other"), "follows another sandbox")):
            status, value = self.classify_with(OPENSHELL, body)
            self.assertIsNone(value["allow_list"])
            self.assertTrue(any(words in reason for reason in value["reasons"]), value["reasons"])
        # Fresh within three of its own intervals.
        self.assertIsNotNone(self.classify_with(OPENSHELL, self.body(age=3 * 600, every=600))[1]["allow_list"])

    def test_only_an_openshell_sandbox_reads_it(self):
        agent = container("none", ("none",))
        status, value = self.classify_with(agent, self.body())
        self.assertEqual((value["level"], value["allow_list"]), ("no_network", None))

    def test_the_list_is_bounded_and_what_it_left_out_is_said(self):
        view = {"policy": {"network_policies": {
            f"r{i}": {"binaries": [{"path": f"/bin/b{j}"} for j in range(40)],
                      "endpoints": [{"host": f"h{i:03d}.example", "ports": [443, 8443],
                                     "rules": [{"allow": {"method": "GET", "path": f"/p{k}"}} for k in range(40)]}]}
            for i in range(200)}}}
        entries, left_out = egress.allow_list_entries(view)
        self.assertEqual((len(entries), left_out), (256, 144))
        self.assertTrue(all(len(e["rules"]) == 32 and len(e["binaries"]) == 32 for e in entries))
        status, value = self.classify_with(OPENSHELL, {**self.body(), "view": view})
        self.assertIn("144 more allow-list entries not listed", value["reasons"])
        # The bundle's contract (the published schema) holds at the bounds.
        docker = Docker([OPENSHELL])
        inputs = egress.collect_inputs(OPENSHELL, docker.container, docker.network)
        inputs.update(openshell_policy={**self.body(), "view": view}, now=self.NOW)
        attrs = BundleTest("test_an_openshell_sandbox_is_answered_observed").build(
            {"mode": "docker", "docker_inspect": OPENSHELL, "env": {}, "egress_inputs": inputs})
        self.assertEqual(len(attrs["egress_containment"]["value"]["allow_list"]), 256)

    def test_shapes_openshell_does_not_write_are_skipped(self):
        view = {"policy": {"network_policies": {
            "a": {"endpoints": [{"host": "ok.example", "port": True}, {"host": ""}, {"port": 443},
                                {"host": "x" * 254}, {"host": "p.example", "port": 70000, "ports": "443"},
                                "junk"], "binaries": "nope"},
            "b": "junk"}}}
        entries, _ = egress.allow_list_entries(view)
        self.assertEqual([(e["host"], e["port"], e["binaries"]) for e in entries],
                         [("ok.example", None, []), ("p.example", None, [])])
        self.assertEqual(egress.allow_list_entries(None), ([], 0))

    def test_the_file_is_read_only_when_it_is_the_collectors(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            self.assertIsNone(egress.read_policy_file(str(path)))
            self.assertIsNone(egress.read_policy_file(None))
            path.write_text("{not json")
            self.assertIsNone(egress.read_policy_file(str(path)))
            path.write_text(json.dumps({"kind": "other"}))
            self.assertIsNone(egress.read_policy_file(str(path)))
            path.write_text(json.dumps(self.body()))
            self.assertEqual(egress.read_policy_file(str(path))["sandbox"], "my-agent")
            path.write_text(" " * (egress.MAX_POLICY_FILE + 1))
            self.assertIsNone(egress.read_policy_file(str(path)))


if __name__ == "__main__":
    unittest.main()
