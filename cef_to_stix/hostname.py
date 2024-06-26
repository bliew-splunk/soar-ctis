from stix2 import AndBooleanExpression, EqualityComparisonExpression, ObjectPath
from stix2.patterns import _PatternExpression

from .constants import DESTINATION_REF, DOMAIN_NAME, NETWORK_TRAFFIC, SOURCE_REF


def handle_hostname(cef_field_value: str) -> _PatternExpression:
    return EqualityComparisonExpression(ObjectPath(DOMAIN_NAME, ["value"]), cef_field_value)


def handle_source_hostname(cef_field_value: str) -> _PatternExpression:
    type_expr = EqualityComparisonExpression(ObjectPath(NETWORK_TRAFFIC, [SOURCE_REF, "type"]), DOMAIN_NAME)
    value_expr = EqualityComparisonExpression(ObjectPath(NETWORK_TRAFFIC, [SOURCE_REF, "value"]), cef_field_value)
    return AndBooleanExpression([type_expr, value_expr])


def handle_destination_hostname(cef_field_value: str) -> _PatternExpression:
    type_expr = EqualityComparisonExpression(ObjectPath(NETWORK_TRAFFIC, [DESTINATION_REF, "type"]), DOMAIN_NAME)
    value_expr = EqualityComparisonExpression(ObjectPath(NETWORK_TRAFFIC, [DESTINATION_REF, "value"]), cef_field_value)
    return AndBooleanExpression([type_expr, value_expr])
