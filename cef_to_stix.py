from stix2 import AndBooleanExpression, EqualityComparisonExpression, IPv4Address, ObjectPath, ObservationExpression
from stix2 import Indicator
import json

STIX_TYPE_IPV4 = "ipv4-addr"

# See result from https://13.54.218.11/rest/cef?page_size=1000
"""
TODO: Implement most common CEF fields
- SRC & DEST for IPv4:
    - IP
    - Hostname
    - Domain
- filename
- file hashes (MD5, SHA1, SHA256)
- URL
- Email

"""


def handle_ip(cef_field_value: str) -> ObservationExpression:
    expression = EqualityComparisonExpression(ObjectPath(STIX_TYPE_IPV4, ["value"]), cef_field_value)
    return ObservationExpression(expression)


def handle_destination_ipv4(cef_field_value: str) -> ObservationExpression:
    dst_ref_type = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "type"]), STIX_TYPE_IPV4)
    dst_ref_value = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "value"]),
                                                 cef_field_value)
    expression = AndBooleanExpression([dst_ref_type, dst_ref_value])
    return ObservationExpression(expression)


def handle_source_ipv4(cef_field_value: str) -> ObservationExpression:
    dst_ref_type = EqualityComparisonExpression(ObjectPath("network-traffic", ["src_ref", "type"]), STIX_TYPE_IPV4)
    dst_ref_value = EqualityComparisonExpression(ObjectPath("network-traffic", ["src_ref", "value"]),
                                                 cef_field_value)
    expression = AndBooleanExpression([dst_ref_type, dst_ref_value])
    return ObservationExpression(expression)


def convert_cef_to_stix_pattern(cef_field_name: str, cef_field_value: str) -> ObservationExpression:
    if cef_field_name == "ip":
        return handle_ip(cef_field_value)
    elif cef_field_name in ("destinationAddress", "destinationTranslatedAddress"):
        return handle_destination_ipv4(cef_field_value)
    elif cef_field_name in ("sourceAddress", "sourceTranslatedAddress"):
        return handle_source_ipv4(cef_field_value)
    else:
        raise NotImplementedError("WIP")


def build_indicator_stix(cef_field_name: str, cef_field_value: str) -> dict:
    pattern = convert_cef_to_stix_pattern(cef_field_name, cef_field_value)

    # TODO: add more fields to the indicator
    # https://stix2.readthedocs.io/en/latest/api/stix2.v21.html#stix2.v21.Indicator
    indicator = Indicator(pattern=pattern,
                          pattern_type="stix")
    indicator_json = str(indicator)
    return json.loads(indicator_json)
