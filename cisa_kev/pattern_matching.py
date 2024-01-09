from typing import Iterable

import fnmatch


def matches_any(value: str, patterns: Iterable[str], case_sensitive: bool = False) -> bool:
    value = value if case_sensitive else value.lower()
    for pattern in patterns:
        pattern = pattern if case_sensitive else pattern.lower()
        if matches(value, pattern, case_sensitive=True):
            return True
    return False


def matches(value: str, pattern: str, case_sensitive: bool = False) -> bool:
    if not case_sensitive:
        value = value.lower()
        pattern = pattern.lower()

    if '*' in pattern:
        return fnmatch.fnmatch(value, pattern)
    else:
        return value == pattern
