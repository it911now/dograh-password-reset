#!/usr/bin/env bash
# Run the password-reset test suite in a throwaway Postgres. Extra args go to pytest.
#   ./run-tests.sh                      # full suite
#   ./run-tests.sh tests/test_config.py # one file
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -p dpr-test -f "$HERE/tests/compose.test.yaml")

# Always remove the stack and its tmpfs data, pass or fail.
trap '"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true' EXIT

"${COMPOSE[@]}" run --rm --build tests "$@"
