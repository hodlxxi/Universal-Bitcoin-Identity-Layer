"""Equivalent PostgreSQL 16 renderings of pinned source catalog expressions."""

import re

_ARRAY_CAST = re.compile(
    r"\(\(ARRAY\[('[a-z0-9_-]+'::character varying(?:, '[a-z0-9_-]+'::character varying)*)\]\)::text\[\]\)"
)
_ASCII_WIRE_CHECK = re.compile(
    r"\(\(\(octet_length\(([a-z_]+)\) >= 1\) AND "
    r"\(octet_length\(\1\) <= [0-9]+\)\) AND \(\1 !~ '\[\^ -~\]'::text\)\)"
)
_RANGE_AS_LEFT_CONJUNCT = re.compile(r"\(\(\(([a-z_]+) >= [0-9]+\) AND \(\1 <= '[0-9]+'::bigint\)\) AND ")


def restored_catalog_definitions(definition: str | None) -> set[str | None]:
    """Compare against the source rendering and the dump/restore rendering."""
    if definition is None:
        return {None}

    def cast_elements(match):
        elements = ", ".join(f"({entry})::text" for entry in match[1].split(", "))
        return f"(ARRAY[{elements}])"

    def flatten_wire_check(match):
        expression = match[0]
        return expression[1:].replace(")) AND (", ") AND (", 1)

    restored = _ARRAY_CAST.sub(cast_elements, definition)
    restored = _ASCII_WIRE_CHECK.sub(flatten_wire_check, restored)
    # Dumped BETWEEN is rendered as two comparisons when restored.
    # Only the left operand of AND is flattened by the parser.
    restored = _RANGE_AS_LEFT_CONJUNCT.sub(lambda match: match[0][1:].replace(")) AND ", ") AND ", 1), restored)
    return {definition, restored}


def valid_catalog_attribute_options(options: object) -> bool:
    """Allow only the server-reserved column version introduced by PG security updates.

    Keep the original value in catalog fingerprints: this is not a normalization
    of user-controlled column options or a waiver of subsequent catalog checks.
    """
    if options is None:
        return True
    if type(options) is not list or len(options) != 1 or type(options[0]) is not str:
        return False
    match = re.fullmatch(r"pg_attver=(0|[1-9][0-9]{0,9})", options[0])
    return match is not None and int(match[1]) <= 4294967295
