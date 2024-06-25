import json
from typing import List

from stix2 import AndBooleanExpression, EqualityComparisonExpression, Indicator, ObjectPath, ObservationExpression, \
    OrBooleanExpression, ParentheticalExpression
from stix2.patterns import _PatternExpression

STIX_TYPE_IPV4 = "ipv4-addr"

# See result from https://13.54.218.11/rest/cef?page_size=1000
#
# For more context on CEF list of fields:
# https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
# This does not cover all fields, but it's a good start. SOAR has slight variations
# Sentinel documentation on CEF field mapping is helpful:
# https://learn.microsoft.com/en-us/azure/sentinel/cef-name-mapping
"""
TODO: Implement most common CEF fields
- base data types:
    ip, port, mac address, url, domain, hash, sha1, sha256, sha512, md5, file name, file path, host name, user name
    process name
- SRC & DEST for IPv4:
    - IP
    - Hostname
    - Domain
- filename
- file hashes (MD5, SHA1, SHA256)
- URL
- Email

"""


def build_indicator_stix(cef_field_name: str, cef_field_value: str) -> dict:
    pattern = convert_cef_to_stix_observation_pattern(cef_field_name, cef_field_value)

    # TODO: add more fields to the indicator
    # https://stix2.readthedocs.io/en/latest/api/stix2.v21.html#stix2.v21.Indicator
    indicator = Indicator(pattern=pattern,
                          pattern_type="stix")
    indicator_json = str(indicator)
    return json.loads(indicator_json)


def convert_multiple_cef_fields_to_stix_observation_pattern(cef_field_names: List[str],
                                                            cef_field_value: str) -> ObservationExpression:
    # each CEF field in cef_field_names share the same value given by cef_field_value.
    # For example (["sourceAddress", "destinationAddress"], "1.2.3.4")
    patterns = []
    for field_name in cef_field_names:
        pattern = get_stix_expression_for_cef_field(field_name, cef_field_value)
        pattern = ParentheticalExpression(pattern)
        patterns.append(pattern)
    expr = OrBooleanExpression(patterns)
    return ObservationExpression(expr)


def convert_cef_to_stix_observation_pattern(cef_field_name: str, cef_field_value: str) -> ObservationExpression:
    pattern = get_stix_expression_for_cef_field(cef_field_name, cef_field_value)
    return ObservationExpression(pattern)


def handle_ip(cef_field_value: str) -> _PatternExpression:
    return EqualityComparisonExpression(ObjectPath(STIX_TYPE_IPV4, ["value"]), cef_field_value)


def handle_destination_ipv4(cef_field_value: str) -> _PatternExpression:
    dst_ref_type = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "type"]), STIX_TYPE_IPV4)
    dst_ref_value = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "value"]),
                                                 cef_field_value)
    return AndBooleanExpression([dst_ref_type, dst_ref_value])


def handle_source_ipv4(cef_field_value: str) -> _PatternExpression:
    dst_ref_type = EqualityComparisonExpression(ObjectPath("network-traffic", ["src_ref", "type"]), STIX_TYPE_IPV4)
    dst_ref_value = EqualityComparisonExpression(ObjectPath("network-traffic", ["src_ref", "value"]),
                                                 cef_field_value)
    return AndBooleanExpression([dst_ref_type, dst_ref_value])


def handle_hostname(cef_field_value: str) -> _PatternExpression:
    return EqualityComparisonExpression(ObjectPath("domain-name", ["value"]), cef_field_value)


def handle_source_hostname(cef_field_value: str) -> _PatternExpression:
    type_expr = EqualityComparisonExpression(ObjectPath("network-traffic", ["src_ref", "type"]), "domain-name")
    value_expr = EqualityComparisonExpression(ObjectPath("network-traffic", ["src_ref", "value"]), cef_field_value)
    return AndBooleanExpression([type_expr, value_expr])


def handle_destination_hostname(cef_field_value: str) -> _PatternExpression:
    type_expr = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "type"]), "domain-name")
    value_expr = EqualityComparisonExpression(ObjectPath("network-traffic", ["dst_ref", "value"]), cef_field_value)
    return AndBooleanExpression([type_expr, value_expr])


MAP_OF_CEF_FIELD_TO_PATTERN_FUNCTION = {
    "ip": handle_ip,
    "destinationAddress": handle_destination_ipv4,
    "destinationTranslatedAddress": handle_destination_ipv4,
    "sourceAddress": handle_source_ipv4,
    "sourceTranslatedAddress": handle_source_ipv4,
    "hostname": handle_hostname,
    "host name": handle_hostname,
    "dvchost": handle_hostname,
    "deviceHostname": handle_hostname,
    "shost": handle_source_hostname,
    "sourceHostName": handle_source_hostname,
    "dhost": handle_destination_hostname,
    "destinationHostName": handle_destination_hostname,
}


def get_stix_expression_for_cef_field(cef_field_name: str, cef_field_value: str) -> _PatternExpression:
    conversion_function = MAP_OF_CEF_FIELD_TO_PATTERN_FUNCTION.get(cef_field_name)
    if conversion_function is None:
        raise NotImplementedError(f"CEF field {cef_field_name} conversion not implemented yet.")
    else:
        return conversion_function(cef_field_value)
