# HODLXXI runtime endpoint map

## Discovery

- `GET /agent/capabilities` — signed runtime capabilities summary.
- `GET /agent/capabilities/schema` — canonical schema for the capabilities document.
- `GET /agent/skills` — task-oriented skill listing that points back to checked-in skill folders.

## Job execution

- `POST /agent/request` — submit a supported job request.
- `GET /agent/jobs/<job_id>` — inspect job state and any final receipt.

## Trust / verification

- `GET /agent/reputation` — aggregate public operating history.
- `GET /agent/attestations` — public signed receipt history.

## Authority note

If this reference and the live runtime differ, the runtime schema and runtime responses override this static document.
