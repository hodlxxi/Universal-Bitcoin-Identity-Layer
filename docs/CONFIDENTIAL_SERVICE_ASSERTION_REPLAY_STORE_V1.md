# Confidential Service Assertion Replay Store V1

## Implemented by this change

The source tree now contains a dedicated PostgreSQL persistence boundary for
confidential-service client-assertion replay markers. The
`PostgresConfidentialServiceAssertionReplayStore` instance is directly
injectable as the `replay_consumer(jti, retention_deadline_exclusive)`
dependency of `issue_service_access_token`.

The table stores only:

- `jti_sha256`: lowercase hexadecimal SHA-256 over the exact UTF-8 bytes of
  the validated assertion JTI; and
- `retention_deadline_exclusive`: the exact integer deadline supplied by the
  existing credential layer.

The raw JTI, assertion, claims, access token, keys, and credential material are
not persisted or logged. PostgreSQL primary-key uniqueness over `jti_sha256`
is the shared multi-worker authority. Consumption is one
`INSERT ... ON CONFLICT DO NOTHING ... RETURNING` decision. A fresh marker can
return true to exactly one caller; retained duplicates and storage failures
return false. There is no process-local, Redis, or filesystem fallback.

The insert uses the PostgreSQL clock to reject a deadline that has already
arrived. Optional cleanup is a separate operation and can delete only rows with
`retention_deadline_exclusive` less than or equal to the current PostgreSQL
integer epoch second. The marker therefore remains present through the final
accepted integer second and becomes eligible at the exclusive deadline. Cleanup
is not required for consume-once correctness and no scheduler is added.

## Still not implemented or active

- HTTP service-token endpoint;
- privacy-safe Full-directory internal HTTP route;
- Social backend connection;
- production confidential-client or signing-key provisioning;
- production privacy-directory alias-secret provisioning;
- production application of the migration;
- nginx private-path enforcement;
- runtime injection or activation; and
- production deployment.

This migration and adapter are a prerequisite only. They do not make the Social
directory or confidential credential delivery live.
