"""Provision only the marked disposable PG16 database, with separate SQL roles."""

import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.models import User, OAuthClient, OAuthToken, OAuthCode, Session, CurrentEntitlementEvidence
from tests.integration.canon_v2_disposable_pg import disposable_postgres_engine

ROLES = ("h588_message_owner", "h588_message_issuer", "h588_message_finalizer", "h588_message_reader")
MIGRATIONS = (
    "2026-07-22_current_entitlement_evidence.sql",
    "2026-08-31_confidential_service_assertion_replay_markers_v1.sql",
    "2026-09-04_social_messaging_device_bindings_v1.sql",
    "2026-09-10_social_messaging_device_binding_authorization_v1.sql",
    "2026-09-13_oauth_session_lifecycle_v1.sql",
    "2026-09-13_social_messaging_mobile_authorization_v1.sql",
    "2026-09-13_social_session_issuance_v1.sql",
    "2026-09-21_social_device_challenge_store_v1.sql",
    "2026-09-22_social_device_ed25519_association_storage_v1.sql",
    "2026-09-23_social_device_admission_receipt_consumption_v1.sql",
    "2026-09-24_social_messaging_recipient_routing_registry_v1.sql",
    "2026-10-02_social_preaccepted_enrollment_v2_atomic_acceptance_storage_v1.sql",
    "2026-10-09_social_device_challenge_revision_v1.sql",
    "2026-10-10_social_session_issuance_v2_provenance_v1.sql",
    "2026-10-12_social_enrollment_v2_finalization_v1.sql",
    "2026-10-14_social_enrollment_v2_freshness_profile_guard_v1.sql",
    "2026-11-15_social_device_request_receipts_v1.sql",
)


@pytest.fixture(scope="module")
def message_pg16():
    if os.environ.get("CANON_V2_DISPOSABLE_PG_ACK") != "1" or not os.environ.get("CANON_V2_TEST_DATABASE_URL"):
        pytest.skip("explicit disposable PG16 required")
    admin = disposable_postgres_engine(os.environ["CANON_V2_TEST_DATABASE_URL"])
    engines = []
    created = False
    try:
        with admin.begin() as db:
            if db.execute(text("SELECT count(*) FROM pg_tables WHERE schemaname='public'")).scalar_one():
                raise RuntimeError("disposable database must be empty")
            for role in ROLES:
                db.exec_driver_sql(
                    f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                )
                db.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {role}")
            db.exec_driver_sql(f"GRANT CREATE ON SCHEMA public TO {ROLES[0]}")
            db.exec_driver_sql(f"GRANT CREATE ON DATABASE canonv2test TO {ROLES[0]}")
        created = True
        for role in ROLES:
            engines.append(
                create_engine(admin.url.set(username=role, password=None), poolclass=NullPool, hide_parameters=True)
            )
        owner, issuer, finalizer, reader = engines
        with owner.begin() as db:
            for model in (User, OAuthClient, OAuthToken, OAuthCode, Session):
                model.__table__.create(db)
            # Current ORM metadata already includes these two later additions;
            # reconstruct the pre-migration core schema before applying SQL.
            db.exec_driver_sql("ALTER TABLE oauth_tokens DROP CONSTRAINT uq_oauth_token_generation_owner")
            db.exec_driver_sql("ALTER TABLE sessions DROP CONSTRAINT uq_session_generation_owner")
            for name in MIGRATIONS:
                if name == "2026-10-09_social_device_challenge_revision_v1.sql":
                    # Report only schema metadata from the marked disposable target.
                    # Keep the migration's exact fail-closed checks untouched.
                    for label, query in (
                        (
                            "attributes",
                            "SELECT attnum,attname,atttypid,atttypmod,attnotnull,attcollation,attstorage,"
                            "attisdropped,atthasdef,attgenerated,attidentity,atthasmissing,attmissingval,"
                            "attislocal,attinhcount,attoptions,attfdwoptions FROM pg_catalog.pg_attribute "
                            "WHERE attrelid='public.social_device_admission_challenges'::regclass "
                            "AND attnum>0 ORDER BY attnum",
                        ),
                        (
                            "constraints",
                            "SELECT conname,pg_catalog.pg_get_constraintdef(oid,false),"
                            "pg_catalog.to_jsonb(pg_constraint) FROM pg_catalog.pg_constraint "
                            "WHERE conrelid='public.social_device_admission_challenges'::regclass ORDER BY conname",
                        ),
                        (
                            "indexes",
                            "SELECT pg_catalog.to_jsonb(i),pg_catalog.pg_get_indexdef(i.indexrelid) "
                            "FROM pg_catalog.pg_index i "
                            "WHERE i.indrelid='public.social_device_admission_challenges'::regclass",
                        ),
                        (
                            "triggers",
                            "SELECT tgname,tgtype,tgisinternal,tgdeferrable,tginitdeferred "
                            "FROM pg_catalog.pg_trigger "
                            "WHERE tgrelid='public.social_device_admission_challenges'::regclass ORDER BY tgname",
                        ),
                    ):
                        print("DISPOSABLE_REVISION_CATALOG", label, db.exec_driver_sql(query).all(), flush=True)
                db.exec_driver_sql((Path("migrations") / name).read_text(), execution_options={"no_parameters": True})
        with admin.begin() as db:
            for role in ROLES[1:]:
                db.exec_driver_sql(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role}")
                db.exec_driver_sql(
                    f"GRANT UPDATE ON users,oauth_clients,oauth_tokens,oauth_codes,sessions,current_entitlement_evidence,oauth_browser_generations,oauth_session_generations,social_messaging_device_bindings,social_messaging_device_authorization_requests,social_device_ed25519_association_chains,social_device_admission_challenges,social_device_enrollment_admission_receipts TO {role}"
                )
                db.exec_driver_sql(f"GRANT UPDATE(client_id) ON social_session_issuers TO {role}")
            # Native issuers and the finalizer keep the existing closed writer
            # profile. The message reader has NO V2 issuance INSERT privilege.
            for role in ROLES[1:3]:
                db.exec_driver_sql(
                    f"GRANT INSERT ON oauth_tokens,social_messaging_device_bindings,social_messaging_device_authorization_requests,social_session_v2_offers,social_session_v2_parents,social_session_v2_acceptances,social_session_v2_issuances TO {role}"
                )
            db.exec_driver_sql(
                f"GRANT INSERT ON social_device_admission_challenges,social_preaccepted_enrollment_v2_atomic_acceptances TO {ROLES[1]}"
            )
            db.exec_driver_sql(
                f"GRANT UPDATE ON social_preaccepted_enrollment_v2_atomic_acceptances TO {ROLES[1]},{ROLES[2]}"
            )
            db.exec_driver_sql(f"GRANT INSERT ON social_preaccepted_enrollment_v2_atomic_acceptances TO {ROLES[2]}")
            db.exec_driver_sql(
                f"GRANT INSERT ON social_device_ed25519_association_chains,social_device_ed25519_association_events,social_device_enrollment_admission_receipts TO {ROLES[2]}"
            )
            db.exec_driver_sql(
                f"GRANT EXECUTE ON FUNCTION public.execute_social_enrollment_v2_native_effects(text,text,text,text,text,text,text) TO {ROLES[2]}"
            )
            db.exec_driver_sql(f"GRANT pg_read_all_settings TO {ROLES[1]},{ROLES[2]}")
            db.exec_driver_sql(
                f"GRANT INSERT ON social_device_request_receipts_v1,social_messaging_recipient_handle_owners,social_messaging_recipient_routing_snapshots,social_messaging_recipient_routing_snapshot_routes,social_messaging_recipient_routing_decisions,social_messaging_recipient_routing_decision_routes,confidential_service_assertion_replay_markers TO {ROLES[1]}"
            )
            db.exec_driver_sql(
                f"GRANT UPDATE ON social_messaging_recipient_handle_owners,social_messaging_recipient_routing_snapshots,social_messaging_recipient_routing_decisions TO {ROLES[1]}"
            )
            db.exec_driver_sql(f"GRANT DELETE ON confidential_service_assertion_replay_markers TO {ROLES[1]}")
            db.exec_driver_sql(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {ROLES[3]}")
            from app.services.social_enrollment_v2_catalog_roles import challenge_writer_privileges_for_relations

            names = db.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'")).scalars().all()
            for table, privileges in challenge_writer_privileges_for_relations(names).items():
                db.exec_driver_sql(f"REVOKE ALL ON public.{table} FROM {ROLES[1]}")
                if privileges:
                    db.exec_driver_sql(f'GRANT {",".join(privileges)} ON public.{table} TO {ROLES[1]}')
            from app.services.social_enrollment_v2_finalization_storage import AUTHORITY_ACLS

            for table, privileges in AUTHORITY_ACLS.items():
                db.exec_driver_sql(f"REVOKE ALL ON public.{table} FROM {ROLES[2]}")
                db.exec_driver_sql(f'GRANT {",".join(privileges)} ON public.{table} TO {ROLES[2]}')
        yield tuple(engines)
    finally:
        for engine in engines:
            engine.dispose()
        if created:
            with admin.begin() as db:
                db.exec_driver_sql("DROP SCHEMA public CASCADE")
                db.exec_driver_sql("CREATE SCHEMA public")
                for role in reversed(ROLES):
                    db.exec_driver_sql(f"DROP OWNED BY {role}")
                    db.exec_driver_sql(f"DROP ROLE {role}")
        admin.dispose()
