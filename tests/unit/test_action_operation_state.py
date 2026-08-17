from app.services.action_operation_storage import (
    ALLOWED_TRANSITIONS,
    OPERATION_STATES,
    SqlAlchemyActionOperationRepository,
    is_allowed_transition,
)


def test_exact_states_and_transitions():
    assert OPERATION_STATES == {"reserved", "executing", "completed", "failed", "indeterminate"}
    assert ALLOWED_TRANSITIONS == {
        ("reserved", "executing"),
        ("reserved", "failed"),
        ("executing", "completed"),
        ("executing", "failed"),
        ("executing", "indeterminate"),
    }
    for current in OPERATION_STATES:
        for next_state in OPERATION_STATES:
            assert is_allowed_transition(current, next_state) == ((current, next_state) in ALLOWED_TRANSITIONS)


def test_repository_transition_methods_encode_only_allowed_edges():
    import inspect

    source = inspect.getsource(SqlAlchemyActionOperationRepository)
    assert '("reserved",)' in source
    assert '("executing",)' in source
    assert '("reserved", "executing")' in source
    for forbidden in ("authorized", "accepted", "denied", "pending", "retrying"):
        assert forbidden not in source
