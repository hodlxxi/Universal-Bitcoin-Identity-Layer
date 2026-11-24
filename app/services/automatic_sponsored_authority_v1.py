"""One-snapshot database lineage check for Current Full consumers.

Historical EFFECTIVE is not current eligibility. Every ancestor must still
have unambiguous, unexpired canonical Full, an active account and exact active
ancestry to the trusted genesis. Bitcoin freshness is bounded by the evidence
TTL; the server-owned coordinator refreshes or invalidates that evidence.
"""

from sqlalchemy import text

from app.services.canonical_genesis_record import GRAPH_ID, XONLY_KEY

SOURCE = "canonical_auto_sponsored_import"
VERSION = "hodlxxi.auto_effective.v1"

_CHECK = text("""
WITH RECURSIVE trail AS (
    SELECT v.*,ARRAY[v.child_xonly_pubkey::text] AS seen,1 AS n
    FROM public.canonical_effective_authority_edges_v1 v
    WHERE v.kind='automatic' AND v.child_xonly_pubkey=:subject
    UNION ALL
    SELECT p.*,t.seen||p.child_xonly_pubkey::text,t.n+1
    FROM trail t JOIN public.canonical_effective_authority_edges_v1 p
      ON p.kind=t.parent_kind AND p.edge_id=t.parent_id
     AND p.child_xonly_pubkey=t.sponsor_xonly_pubkey AND p.child_depth=t.child_depth-1
    WHERE t.n<2288 AND NOT p.child_xonly_pubkey::text=ANY(t.seen)
), latest AS (
    SELECT e.*,row_number() OVER(PARTITION BY e.subject_pubkey ORDER BY e.observed_at DESC,e.created_at DESC,e.evidence_id DESC) AS rank,
      count(*) OVER(PARTITION BY e.subject_pubkey,e.observed_at,e.created_at) AS ties
    FROM public.current_entitlement_evidence e
    WHERE e.subject_pubkey IN(SELECT sponsor_xonly_pubkey FROM trail)
)
SELECT
    (SELECT count(*) FROM trail)=(SELECT child_depth FROM trail WHERE n=1)
    AND (SELECT count(*) FROM trail WHERE child_depth=1)=1
    AND EXISTS(SELECT 1 FROM trail t JOIN public.canonical_genesis_records g ON g.record_id=t.genesis_record_id
        WHERE t.child_depth=1 AND t.sponsor_xonly_pubkey=:genesis AND g.graph_or_protocol_id=:graph
        AND g.x_only_public_key=:genesis AND g.lifecycle_state='effective' AND g.effective_at<=:now
        AND g.record_id=(SELECT genesis_record_id FROM trail WHERE n=1)
        AND (SELECT count(*) FROM public.canonical_genesis_records WHERE graph_or_protocol_id=:graph)=1)
    AND NOT EXISTS(SELECT 1 FROM trail t LEFT JOIN latest e ON e.subject_pubkey=t.sponsor_xonly_pubkey AND e.rank=1
        LEFT JOIN public.users u ON u.pubkey=t.sponsor_xonly_pubkey
        WHERE e.evidence_id IS NULL OR e.ties<>1 OR u.is_active IS DISTINCT FROM TRUE
        OR e.identity_class<>'full' OR e.current_full_relation_satisfied IS DISTINCT FROM TRUE
        OR e.revoked_at IS NOT NULL OR e.observed_at>:now OR e.valid_until<=:now
        OR e.valid_until<(SELECT valid_until FROM public.current_entitlement_evidence WHERE evidence_id=:eid)
        OR (e.evidence_source=:source AND NOT EXISTS(
            SELECT 1 FROM public.canonical_auto_entitlement_observations_v1 o
            JOIN public.canonical_auto_effective_edges_v1 a USING(pair_sha256)
            WHERE o.evidence_id=e.evidence_id AND o.current_eligible IS TRUE
              AND o.source_evidence_sha256=e.source_evidence_sha256
              AND o.observed_at=e.observed_at AND o.valid_until=e.valid_until
              AND a.child_xonly_pubkey=e.subject_pubkey)))
    AND NOT EXISTS(SELECT 1 FROM trail t JOIN public.canonical_auto_admission_revocations_v1 r ON r.pair_sha256=t.edge_id
        WHERE t.kind='automatic')
    AND EXISTS(SELECT 1 FROM public.canonical_auto_entitlement_observations_v1 o
        JOIN public.canonical_auto_effective_edges_v1 a USING(pair_sha256)
        JOIN public.current_entitlement_evidence e USING(evidence_id)
        WHERE o.evidence_id=:eid AND a.child_xonly_pubkey=:subject
        AND e.subject_pubkey=:subject AND e.evidence_source=:source AND e.evidence_version=:version
        AND o.source_evidence_sha256=e.source_evidence_sha256
        AND o.current_eligible=e.current_full_relation_satisfied AND o.current_eligible IS TRUE)
""")


def current_automatic_lineage_is_valid(session, subject, evidence_id, *, now):
    """No mutation, RPC injection, transaction ownership or nested commit."""
    return (
        session.execute(
            _CHECK,
            {
                "subject": subject,
                "eid": evidence_id,
                "now": now,
                "genesis": XONLY_KEY,
                "graph": GRAPH_ID,
                "source": SOURCE,
                "version": VERSION,
            },
        ).scalar_one()
        is True
    )
