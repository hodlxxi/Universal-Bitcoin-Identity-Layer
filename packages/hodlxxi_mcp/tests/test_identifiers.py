import pytest

from hodlxxi_mcp.errors import InvalidIdentifierError
from hodlxxi_mcp.identifiers import validate_identifier, validate_limit, validate_offset


@pytest.mark.parametrize(
    "value",
    [
        "hodlxxi-herald-01",
        "hodlxxi-herald-covenant-v1",
        "28513434-0cba-440f-acf1-fce8958c971c",
        "report:20260712",
    ],
)
def test_valid_identifiers(value: str) -> None:
    assert validate_identifier(value, label="id") == value


@pytest.mark.parametrize("value", ["", "../secret", "/absolute", "a?x=1", "a#fragment", "a b", "x" * 129])
def test_invalid_identifiers(value: str) -> None:
    with pytest.raises(InvalidIdentifierError):
        validate_identifier(value, label="id")


@pytest.mark.parametrize("value", [1, 20, 100])
def test_valid_limits(value: int) -> None:
    assert validate_limit(value) == value


@pytest.mark.parametrize("value", [0, 101, -1, True, 1.5])
def test_invalid_limits(value) -> None:
    with pytest.raises(InvalidIdentifierError):
        validate_limit(value)


@pytest.mark.parametrize("value", [0, 1, 1_000_000])
def test_valid_offsets(value: int) -> None:
    assert validate_offset(value) == value


@pytest.mark.parametrize("value", [-1, 1_000_001, True, 1.5])
def test_invalid_offsets(value) -> None:
    with pytest.raises(InvalidIdentifierError):
        validate_offset(value)
