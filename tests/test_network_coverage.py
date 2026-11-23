import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("coverage", Path(__file__).resolve().parents[1] / "tools/check_network_coverage.py")
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class NetworkCoverage(unittest.TestCase):
    def setUp(self):
        self.wasm = {"name": "envoy.filters.network.wasm", "typed_config": {"config": {
            "root_id": "crowdsec-network", "configuration": {"value": json.dumps({"crowdsec": {"lapi": {"enabled": True}}})}}}}
        self.proxy = {"name": "envoy.filters.network.tcp_proxy"}

    def listener(self, filters):
        return {"name": "tcp-test", "address": {"socket_address": {}}, "filter_chains": [{"filters": filters}]}

    def test_all_chains_including_default_are_checked(self):
        value = self.listener([self.wasm, self.proxy])
        value["default_filter_chain"] = {"filters": [self.proxy]}
        checked, failures = coverage.uncovered(value)
        self.assertEqual(checked, 2)
        self.assertEqual(len(failures), 1)

    def test_new_tcp_listener_cannot_silently_bypass(self):
        config = {"configs": [{"dynamic_listeners": [{"active_state": {"listener": self.listener([self.wasm, self.proxy])}},
                                                     {"active_state": {"listener": self.listener([self.proxy])}}]}]}
        self.assertEqual(len(coverage.uncovered(config)[1]), 1)

    def test_network_filter_must_precede_proxy_and_be_enabled(self):
        self.assertEqual(len(coverage.uncovered(self.listener([self.proxy, self.wasm]))[1]), 1)
        self.wasm["typed_config"]["config"]["configuration"]["value"] = '{"crowdsec":{"lapi":{"enabled":false}}}'
        self.assertEqual(len(coverage.uncovered(self.listener([self.wasm, self.proxy]))[1]), 1)

    def test_combined_filters_share_vm_when_reusing_a_bouncer_key(self):
        import copy
        http_plugin = copy.deepcopy(self.wasm)
        http_plugin["name"] = "envoy.filters.http.wasm"
        http_plugin["typed_config"]["config"]["root_id"] = "crowdsec"
        http_plugin["typed_config"]["config"]["vm_config"] = {"vm_id": "other"}
        manager = {"name": "envoy.filters.network.http_connection_manager", "typed_config": {
            "http_filters": [http_plugin]}}
        self.assertEqual(len(coverage.uncovered(self.listener([self.wasm, manager]))[1]), 1)
        self.wasm["typed_config"]["config"]["vm_config"] = {"vm_id": "other"}
        self.assertEqual(coverage.uncovered(self.listener([self.wasm, manager]))[1], [])

    def test_gateway_health_endpoints_are_excluded_but_routed_ports_are_checked(self):
        value = self.listener([self.proxy])
        value["name"] = "envoy-gateway-proxy-ready-::-19003"
        value["address"]["socket_address"]["port_value"] = 19003
        self.assertEqual(coverage.uncovered(value), (0, []))
        value["name"] = "public-listener"
        self.assertEqual(len(coverage.uncovered(value)[1]), 1)

    def test_udp_and_quic_are_excluded(self):
        value = self.listener([self.proxy])
        value["address"]["socket_address"]["protocol"] = "UDP"
        self.assertEqual(coverage.uncovered(value), (0, []))


if __name__ == "__main__":
    unittest.main()
