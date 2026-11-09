"""Pure server-selected freshness vocabulary; no current authority or runtime wiring.

Legacy signed bytes omit freshnessProfile and retain a ten-second maximum.
The new native V2 profile MUST sign its explicit name in both JWS payloads.
Consumers require the exact server-configured profile; the payload cannot select
their authorization policy. Neither profile changes a signed expiresAt value.
"""

LEGACY_10S = "legacy-10s"
NATIVE_V2_60S_V1 = "native-v2-60s-v1"
PROFILE_FIELD = "freshnessProfile"


def max_lifetime_ms(profile=LEGACY_10S):
    if type(profile) is not str:
        raise ValueError("social enrollment freshness profile denied")
    if profile == LEGACY_10S:
        return 10_000
    if profile == NATIVE_V2_60S_V1:
        return 60_000
    raise ValueError("social enrollment freshness profile denied")


def payload_fields(fields, profile=LEGACY_10S):
    max_lifetime_ms(profile)
    return set(fields) | ({PROFILE_FIELD} if profile == NATIVE_V2_60S_V1 else set())


def payload_marker(profile=LEGACY_10S):
    max_lifetime_ms(profile)
    return {PROFILE_FIELD: profile} if profile == NATIVE_V2_60S_V1 else {}


def validate_payload_marker(value, profile=LEGACY_10S):
    max_lifetime_ms(profile)
    if profile == LEGACY_10S:
        if PROFILE_FIELD in value:
            raise ValueError("social enrollment freshness profile denied")
    elif type(value.get(PROFILE_FIELD)) is not str or value[PROFILE_FIELD] != profile:
        raise ValueError("social enrollment freshness profile denied")
