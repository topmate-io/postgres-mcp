#!/usr/bin/env python3
# scripts/mint_person_token.py
"""Mint a personal bearer token for topmate-internal-mcp PersonAuth (LOOP-664).

Usage: python scripts/mint_person_token.py <person-name>

Prints the raw token ONCE (hand it to the person over a secure channel; it is
never stored) and the PERSON_TOKENS JSON fragment to merge into the AWS
Secrets Manager secret topmate/postgres-mcp/person-tokens.
"""

import hashlib
import json
import secrets
import sys


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("usage: mint_person_token.py <person-name>", file=sys.stderr)
        return 1
    name = sys.argv[1].strip()
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    print(f"Raw token for {name} (share once, never store):\n  {token}\n")
    print(f"PERSON_TOKENS fragment:\n  {json.dumps(name)}: {json.dumps(digest)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
