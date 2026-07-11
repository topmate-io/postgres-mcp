"""Unit tests for the per-person token registry (LOOP-664 M1).

PERSON_TOKENS is a JSON object mapping person name -> sha256 hex digest of
that person's raw bearer token. The raw token never appears in config.
"""

import hashlib

import pytest

from postgres_mcp.person_auth import PersonTokenRegistry


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def test_verify_known_token_returns_person_name():
    reg = PersonTokenRegistry(raw=f'{{"dharsan": "{_digest("tok-abc")}"}}')
    assert reg.verify("tok-abc") == "dharsan"


def test_verify_unknown_token_returns_none():
    reg = PersonTokenRegistry(raw=f'{{"dharsan": "{_digest("tok-abc")}"}}')
    assert reg.verify("tok-WRONG") is None


def test_verify_empty_presented_returns_none():
    reg = PersonTokenRegistry(raw=f'{{"dharsan": "{_digest("tok-abc")}"}}')
    assert reg.verify("") is None


def test_empty_config_verifies_nothing():
    reg = PersonTokenRegistry(raw="")
    assert len(reg) == 0
    assert reg.verify("anything") is None


def test_digest_matching_is_case_insensitive():
    reg = PersonTokenRegistry(raw=f'{{"ci": "{_digest("tok-ci").upper()}"}}')
    assert reg.verify("tok-ci") == "ci"


def test_malformed_json_raises_value_error():
    with pytest.raises(ValueError, match="not valid JSON"):
        PersonTokenRegistry(raw="{not json")


def test_non_object_json_raises_value_error():
    with pytest.raises(ValueError, match="JSON object"):
        PersonTokenRegistry(raw='["a", "b"]')


def test_non_sha256_digest_raises_value_error():
    with pytest.raises(ValueError, match="sha256 hex digest"):
        PersonTokenRegistry(raw='{"dharsan": "short"}')


def test_duplicate_token_digest_across_names_raises():
    shared = _digest("tok-shared")
    with pytest.raises(ValueError, match="duplicate token digest"):
        PersonTokenRegistry(raw=f'{{"alice": "{shared}", "bob": "{shared}"}}')


def test_two_people_resolve_independently():
    raw = f'{{"dharsan": "{_digest("tok-a")}", "ci-bot": "{_digest("tok-b")}"}}'
    reg = PersonTokenRegistry(raw=raw)
    assert reg.verify("tok-a") == "dharsan"
    assert reg.verify("tok-b") == "ci-bot"
    assert len(reg) == 2
