from stix2 import AndBooleanExpression, EqualityComparisonExpression, ObjectPath
from stix2.patterns import _PatternExpression

from .constants import STIX_TYPE_IPV4, NETWORK_TRAFFIC, DESTINATION_REF, SOURCE_REF


def handle_ip(cef_field_value: str) -> _PatternExpression:
    return EqualityComparisonExpression(ObjectPath(STIX_TYPE_IPV4, ["value"]), cef_field_value)


def handle_destination_ipv4(cef_field_value: str) -> _PatternExpression:
    dst_ref_type = EqualityComparisonExpression(ObjectPath(NETWORK_TRAFFIC, [DESTINATION_REF, "type"]), STIX_TYPE_IPV4)
    dst_ref_value = EqualityComparisonExpression(ObjectPath(NETWORK_TRAFFIC, [DESTINATION_REF, "value"]),
                                                 cef_field_value)
    return AndBooleanExpression([dst_ref_type, dst_ref_value])


def handle_source_ipv4(cef_field_value: str) -> _PatternExpression:
    dst_ref_type = EqualityComparisonExpression(ObjectPath(NETWORK_TRAFFIC, [SOURCE_REF, "type"]), STIX_TYPE_IPV4)
    dst_ref_value = EqualityComparisonExpression(ObjectPath(NETWORK_TRAFFIC, [SOURCE_REF, "value"]),
                                                 cef_field_value)
    return AndBooleanExpression([dst_ref_type, dst_ref_value])
