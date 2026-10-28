def self_subject(value: int) -> int:
    return value + 1


def test_self_witness() -> None:
    assert self_subject(1) == 2
