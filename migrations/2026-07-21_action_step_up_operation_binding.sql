-- 2026-07-21: Bind each step-up challenge to at most one action operation.
-- Operator order:
--   1. migrations/2026-07-20_action_step_up_challenges.sql
--   2. migrations/2026-07-20_action_operations.sql
--   3. migrations/2026-07-21_action_step_up_operation_binding.sql

BEGIN;

DO $$
BEGIN
  IF to_regclass('action_step_up_challenges') IS NULL
     OR to_regclass('action_operations') IS NULL THEN
    RAISE EXCEPTION 'required action tables do not exist';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'uq_action_operations_step_up_challenge'
      AND conrelid = 'action_operations'::regclass
  ) THEN
    ALTER TABLE action_operations
      ADD CONSTRAINT uq_action_operations_step_up_challenge
      UNIQUE (step_up_challenge_id);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_action_operations_step_up_challenge'
      AND conrelid = 'action_operations'::regclass
  ) THEN
    ALTER TABLE action_operations
      ADD CONSTRAINT fk_action_operations_step_up_challenge
      FOREIGN KEY (step_up_challenge_id)
      REFERENCES action_step_up_challenges (challenge_id);
  END IF;
END
$$;

COMMIT;
