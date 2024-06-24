from cef_to_stix import convert_cef_to_stix_observation_pattern, build_indicator_stix
import pytest


def compare_stix_pattern_to_string(stix_pattern, expected_string):
    assert str(stix_pattern) == expected_string


# Convert from Splunk SOAR CEF field name to STIX2 pattern
class TestCEFToSTIXPattern:

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


class TestBuildIndicatorSTIXJSON:

    def test_ipv4(self):
        indicator_json = build_indicator_stix("ip", "1.2.3.4")
        assert indicator_json["id"].startswith("indicator--")
        assert indicator_json["type"] == "indicator"
        assert indicator_json["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
        assert indicator_json["pattern_type"] == "stix"
