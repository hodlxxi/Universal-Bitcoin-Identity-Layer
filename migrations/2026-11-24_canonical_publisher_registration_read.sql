-- Root refresh resolves the trusted registration and its registered outpoints.
-- Separate publisher must read these legacy tables without acquiring DML.
GRANT SELECT ON public.trusted_covenant_registrations,
    public.trusted_covenant_registered_outpoints TO hodlxxi_canonical_publisher;

DO $$
DECLARE
    relation regclass;
BEGIN
    FOREACH relation IN ARRAY ARRAY[
        'public.trusted_covenant_registrations'::regclass,
        'public.trusted_covenant_registered_outpoints'::regclass
    ] LOOP
        IF NOT has_table_privilege('hodlxxi_canonical_publisher', relation, 'SELECT')
            OR has_any_column_privilege('hodlxxi_canonical_publisher', relation, 'INSERT,UPDATE,REFERENCES')
            OR has_table_privilege('hodlxxi_canonical_publisher', relation, 'DELETE,TRUNCATE,TRIGGER')
        THEN
            RAISE EXCEPTION 'unexpected canonical publisher registration ACL: %', relation;
        END IF;
    END LOOP;
END;
$$;
