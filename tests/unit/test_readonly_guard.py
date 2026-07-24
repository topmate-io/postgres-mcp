import pytest

from postgres_mcp.readonly_guard import is_read_only_sql


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "  select * from t",
        "WITH x AS (SELECT 1) SELECT * FROM x",
        "EXPLAIN SELECT 1",
        "SHOW server_version",
        "-- comment\nSELECT 1",
        "/* c */ TABLE users",
    ],
)
def test_read_only_allowed(sql):
    assert is_read_only_sql(sql) is True


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE t SET a=1",
        "DELETE FROM t",
        "INSERT INTO t VALUES (1)",
        "DROP TABLE t",
        "EXPLAIN ANALYZE SELECT 1",
        "SELECT 1; DROP TABLE t",
        "",
    ],
)
def test_non_read_only_rejected(sql):
    assert is_read_only_sql(sql) is False
