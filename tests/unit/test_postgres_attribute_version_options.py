"""Closed compatibility for PostgreSQL's internal attribute version option."""

import pytest

from app.services.postgres_catalog_definitions import valid_catalog_attribute_options


@pytest.mark.parametrize("options", [None, ["pg_attver=0"], ["pg_attver=27681208"], ["pg_attver=4294967295"]])
def test_only_native_attribute_version_is_accepted(options):
    assert valid_catalog_attribute_options(options)


@pytest.mark.parametrize(
    "options",
    [
        [],
        "pg_attver=1",
        ("pg_attver=1",),
        [None],
        ["pg_attver=1", "pg_attver=1"],
        ["pg_attver=1", "n_distinct=1"],
        ["n_distinct=1"],
        ["pg_attver=01"],
        ["pg_attver=-1"],
        ["pg_attver=4294967296"],
        ["pg_attver=1\n"],
        ["pg_attver=0/1"],
        ["pg_other=1"],
    ],
)
def test_other_attribute_options_fail_closed(options):
    assert not valid_catalog_attribute_options(options)
