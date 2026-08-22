# Canonical Root Entitlement Refresh Timer V1

This contract schedules the existing canonical-root entitlement refresh runner. The
repository files are inert source assets: they do not install, enable, start, reload,
or otherwise activate themselves.

## Timing and failure model

Current entitlement evidence has a 300-second TTL. Each timer starts 30 seconds after
boot and schedules the next run 120 seconds after the preceding oneshot becomes
inactive. The 120-second post-completion cadence leaves time before evidence expiry;
it is not a guarantee that a refresh will succeed.

The service propagates runner failure. It has no restart policy and the timer retries
only at its next activation. If refreshes stop or fail, existing evidence expires
after its 300-second TTL and authorization fails closed. Operators must never convert
a refresh failure into Limited or Full evidence or manufacture fallback evidence.
The runner remains the subject-scoped, non-blocking exclusive lock authority.

## Staging-first rollout

Perform these steps in order:

1. Install the staging service and timer through the separately authorized host
   configuration process, without enabling the timer yet.
2. Run the staging service as a manual oneshot and verify a successful refresh before
   enabling either timer.
3. Enable only the staging timer.
4. Observe at least three successful staging cycles at the post-completion cadence.
5. Verify both Full and Limited Social projections from valid entitlement evidence;
   this is observation of existing behavior, not a Social policy change.
6. Install the production service and timer through the authorized host configuration
   process, leaving the production timer disabled.
7. Run the production service as a manual oneshot and verify success.
8. Enable the production timer and observe its refresh results.

## Rollback

Rollback is the reverse environment order: disable the production timer first if it
was enabled, then disable the staging timer. Remove deployed unit copies only through
the separately authorized host configuration process. Do not reinterpret, replace,
or manufacture evidence during rollback. Existing evidence naturally expires and the
system fails closed.

## Evidence growth and boundaries

Evidence rows are immutable. At a 120-second cadence, one subject has an upper bound
of about 720 successful refreshes per day (fewer when an exact replay is unchanged).
This change makes no retention-policy change.

This contract makes no Social, OAuth, database-schema, policy, bootstrap, or
application change. It adds no grant, fallback identity, authority override, runner,
RPC client, or scheduler other than the two systemd timers. It does not inspect
secrets, and no secret value belongs in these assets.
