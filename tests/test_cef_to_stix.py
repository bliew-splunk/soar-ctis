from cef_to_stix import convert_cef_to_stix_observation_pattern, build_indicator_stix, \
    convert_multiple_cef_fields_to_stix_observation_pattern
import pytest


def compare_stix_pattern_to_string(stix_pattern, expected_string):
    assert str(stix_pattern) == expected_string


"""
Convert from Splunk SOAR CEF field name to STIX2 pattern
network-traffic spec: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_rgnc3w40xy

Regarding `network-traffic.dst_ref and .src_ref`:
Specifies the destination of the network traffic, as a reference to a Cyber-observable Object.
The object referenced MUST be of type ipv4-addr, ipv6-addr, mac-addr, or domain-name (for cases where the IP address for a domain name is unknown).
"""


class TestIndividualCEFFieldToSTIXPattern:

    def test_ipv4(self):
        # the ip CEF field is assumed to be an IPv4 address?
        compare_stix_pattern_to_string(
            convert_cef_to_stix_observation_pattern("ip", "1.2.3.4"), "[ipv4-addr:value = '1.2.3.4']")

    def test_ipv6(self):
        raise NotImplementedError

    @pytest.mark.parametrize("cef_field", ("destinationAddress", "destinationTranslatedAddress"))
    def test_destination_ip_address(self, cef_field):
        compare_stix_pattern_to_string(
            convert_cef_to_stix_observation_pattern(cef_field, '203.0.113.33/32'),
            "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32']")

    @pytest.mark.parametrize("cef_field", ("sourceAddress", "sourceTranslatedAddress"))
    def test_source_ip_address(self, cef_field):
        compare_stix_pattern_to_string(
            convert_cef_to_stix_observation_pattern(cef_field, '2.3.4.5'),
            "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '2.3.4.5']")

    @pytest.mark.parametrize("cef_field", ["hostname", "host name", "dvchost", "deviceHostname"])
    def test_hostname_with_no_context(self, cef_field):
        compare_stix_pattern_to_string(
            convert_cef_to_stix_observation_pattern(cef_field, 'example.com'),
            "[domain-name:value = 'example.com']")

    @pytest.mark.parametrize("cef_field", ("shost", "sourceHostName"))
    def test_source_hostname(self, cef_field):
        compare_stix_pattern_to_string(
            convert_cef_to_stix_observation_pattern(cef_field, 'example.com'),
            "[network-traffic:src_ref.type = 'domain-name' AND network-traffic:src_ref.value = 'example.com']")

    @pytest.mark.parametrize("cef_field", ("dhost", "destinationHostName"))
    def test_destination_hostname(self, cef_field):
        compare_stix_pattern_to_string(
            convert_cef_to_stix_observation_pattern(cef_field, 'example.com'),
            "[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com']")


class TestMultipleCEFFieldToSTIXPattern:
    def test_destination_and_source_ipv4(self):
        pattern = convert_multiple_cef_fields_to_stix_observation_pattern(["sourceAddress", "destinationAddress"],
                                                                          "1.2.3.4")
        pattern_str = str(pattern)
        expected = ("[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '1.2.3.4')"
                    " OR (network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '1.2.3.4')]")
        assert pattern_str == expected

    def test_hostname_aliases(self):
        pattern = convert_multiple_cef_fields_to_stix_observation_pattern(
            ["sourceHostName", "destinationHostName", "host name"],
            "example.com")
        pattern_str = str(pattern)
        expected_source_host_name_pattern = "network-traffic:src_ref.type = 'domain-name' AND network-traffic:src_ref.value = 'example.com'"
        expected_destination_host_name_pattern = "network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com'"
        expected_hostname_pattern = "domain-name:value = 'example.com'"
        expected = f"[({expected_source_host_name_pattern}) OR ({expected_destination_host_name_pattern}) OR ({expected_hostname_pattern})]"
        assert pattern_str == expected


class TestBuildIndicatorSTIXJSON:

    def test_ipv4(self):
        indicator_json = build_indicator_stix("ip", "1.2.3.4")
        assert indicator_json["id"].startswith("indicator--")
        assert indicator_json["type"] == "indicator"
        assert indicator_json["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
        assert indicator_json["pattern_type"] == "stix"
