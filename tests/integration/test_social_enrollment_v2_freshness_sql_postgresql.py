"""Opt-in isolated SQL format probes on transaction-local TEMP table copies.

No cluster, role, persistent table or migration creation. The separately
provisioned original and native targets are validated by the existing fixture.
Only the installed trigger's byte/shape semantics are exercised here; these
probes grant no device/current authority. The complete native tests stay intact.
"""

import pytest
from sqlalchemy import MetaData, Table, text
from sqlalchemy.exc import DBAPIError

from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as durable
from tests.integration.test_social_enrollment_v2_finalization_postgresql import native_target
from tests.unit.test_social_enrollment_v2_freshness_sql_guard import SQL_CASES, _freshness_sql_case


@pytest.mark.parametrize("case", SQL_CASES)
def test_freshness_installed_sql_closed_profiles_and_lifetimes(native_target, case):
    ddl, runtime = native_target
    pending, accepted, allowed = _freshness_sql_case(case)
    # One private connection, one local temp table and automatic rollback. The
    # full native decision/effect ledgers and all real tables are untouched.
    with ddl.connect() as connection:
        root = connection.begin()
        try:
            connection.exec_driver_sql(
                "CREATE TEMP TABLE freshness_guard_probe "
                "(LIKE public.social_preaccepted_enrollment_v2_atomic_acceptances INCLUDING ALL) ON COMMIT DROP"
            )
            connection.exec_driver_sql(
                "CREATE TRIGGER freshness_guard_probe_trigger BEFORE INSERT OR UPDATE OR DELETE "
                "ON freshness_guard_probe FOR EACH ROW EXECUTE FUNCTION public.guard_social_preaccepted_v2_acceptance_v1()"
            )
            table = Table("freshness_guard_probe", MetaData(), autoload_with=connection)
            connection.execute(table.insert().values(**pending))
            update = table.update().where(table.c.reservation_id == pending["reservation_id"]).values(**accepted)
            if allowed:
                assert connection.execute(update).rowcount == 1
                assert connection.execute(text("SELECT state FROM freshness_guard_probe")).scalar_one() == "accepted"
            else:
                with pytest.raises(DBAPIError) as failure:
                    connection.execute(update)
                assert failure.value.orig.pgcode == "P0001"
        finally:
            root.rollback()
