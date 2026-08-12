# Canonical Recognized Covenant Funding Set V1

This dormant primitive is an immutable, registration-bound allowlist of funding outpoints that the protocol has explicitly recognized. It does not discover outputs and does not activate entitlement behavior.

The referenced `TrustedCovenantRegistration` remains authoritative. Its one incoming and one outgoing outpoint are immutable registration anchors, not an exhaustive balance. Every effective funding set contains both anchors exactly and may add any number of recognized outpoints. Incoming means sponsor to registration subject (child); outgoing means subject to counterparty (sponsor). Every outpoint must use the corresponding authoritative mirrored-pair witness script.

An effective set has at least one outpoint in each direction. Counts and amounts need not pair: three incoming outpoints and two outgoing outpoints are valid. Membership is explicit. Outputs found by wallet scans, Bitcoin RPC, `listunspent`, `scantxoutset`, script matching, amount matching, or wallet position are never added automatically. Unsolicited dust therefore cannot change canonical membership.

Records use proposed, effective, disputed, superseded, and revoked states. Historical records are retained, while at most one effective set exists per registration. A changed composition is a successor record, never silent mutation.

Recognized funding set is not current unspent balance. Recognized outpoints may later be spent, unconfirmed, unavailable, or confirmed and unspent; a separate observation layer may evaluate that state.

For a later ordinary admission-edge policy only, incoming recognized current balance is sponsor-to-child and outgoing is child-to-sponsor. The future child rule is `incoming > 0` and `outgoing >= incoming`. This contract does not compute it, does not aggregate across pairs or counterparties, and does not change admission-edge evaluation.

Genesis/root has no sponsor edge. This contract makes no decision about root Full semantics and contains no E923 special case. It writes no `CurrentEntitlementEvidence`, invokes no runtime materializer, and performs no Bitcoin or wallet operation.
