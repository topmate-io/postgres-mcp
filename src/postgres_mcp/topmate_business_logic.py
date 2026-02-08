"""Topmate-specific SQL patterns and troubleshooting guide."""

import logging
import os
import requests

logger = logging.getLogger(__name__)


class TopmateBuisnessLogic:
    """Fetches business logic patterns from external Topmate Logic Hub."""

    def __init__(self):
        self.base_url = os.getenv("TOPMATE_LOGIC_HUB_BASE_URL")
        self.api_key = os.getenv("TOPMATE_LOGIC_HUB_API_KEY")

        # Validate configuration without making requests during init
        if not self.base_url or not self.api_key:
            raise ValueError(
                "TOPMATE_LOGIC_HUB_BASE_URL and TOPMATE_LOGIC_HUB_API_KEY environment variables must be set"
            )

    def get_rules(self):
        """Fetch business rules from the Topmate Logic Hub."""
        url = f"{self.base_url}/api/rules/json"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        return response.json()

    def get_patterns(self):
        """Fetch SQL patterns from the Topmate Logic Hub."""
        url = f"{self.base_url}/api/patterns/json"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        return response.json()


# Topmate database schema reference and common query patterns
TOPMATE_SCHEMA_GUIDE = {
    "description": "Topmate database schema reference and SQL patterns",
    "core_tables": {
        "booking_booking": {
            "description": "Main bookings/transactions table",
            "key_columns": {
                "id": "UUID primary key",
                "price": "Booking price (use for GMV calculations)",
                "expert_earnings": "Amount paid to expert",
                "status": "Booking status (completed, cancelled, etc.)",
                "created": "Booking creation timestamp",
                "expert_id": "Foreign key to user_user",
                "service_id": "Foreign key to services_service",
                "currency": "JSON field with currency info",
                "testing": "Boolean - filter out test bookings",
            },
            "common_filters": {
                "completed_bookings": "status = 'completed'",
                "exclude_test": "testing = false",
                "date_range": "created >= 'YYYY-MM-DD' AND created < 'YYYY-MM-DD'",
            },
        },
        "user_user": {
            "description": "Users table (experts and consumers)",
            "key_columns": {
                "id": "Integer primary key",
                "email": "User email",
                "first_name": "First name",
                "last_name": "Last name",
                "is_active": "Account active status",
                "is_staff": "Staff/admin flag",
                "is_superuser": "Superuser flag",
                "date_joined": "Registration date",
            },
            "common_filters": {
                "active_users": "is_active = true",
                "exclude_staff": "is_staff = false AND is_superuser = false",
            },
        },
        "services_service": {
            "description": "Services offered by experts",
            "key_columns": {
                "id": "Integer primary key",
                "title": "Service title",
                "price": "Service price",
                "expert_id": "Foreign key to user_user",
                "is_active": "Service active status",
                "service_type": "Type of service",
            },
        },
        "follower_follower": {
            "description": "Follower/consumer relationships",
            "key_columns": {
                "id": "Integer primary key",
                "expert_id": "Expert user ID",
                "follower_id": "Follower user ID",
                "created": "Follow date",
            },
        },
    },
    "common_queries": {
        "monthly_gmv": """
SELECT
    DATE_TRUNC('month', created) as month,
    COUNT(*) as total_bookings,
    SUM(price) as total_gmv,
    SUM(expert_earnings) as expert_earnings
FROM booking_booking
WHERE status = 'completed'
  AND testing = false
  AND created >= 'YYYY-MM-01'
  AND created < 'YYYY-MM-01'
GROUP BY DATE_TRUNC('month', created)
ORDER BY month;
""",
        "expert_earnings": """
SELECT
    u.id as expert_id,
    u.email,
    u.first_name || ' ' || u.last_name as expert_name,
    COUNT(b.id) as total_bookings,
    SUM(b.price) as total_gmv,
    SUM(b.expert_earnings) as total_earnings
FROM user_user u
JOIN booking_booking b ON u.id = b.expert_id
WHERE b.status = 'completed'
  AND b.testing = false
  AND b.created >= 'YYYY-MM-DD'
GROUP BY u.id, u.email, u.first_name, u.last_name
ORDER BY total_gmv DESC;
""",
        "user_growth": """
SELECT
    DATE_TRUNC('month', date_joined) as month,
    COUNT(*) as new_users
FROM user_user
WHERE is_active = true
GROUP BY DATE_TRUNC('month', date_joined)
ORDER BY month;
""",
    },
}

# Troubleshooting guide for common SQL issues
TROUBLESHOOTING_GUIDE = {
    "description": "Troubleshooting guide for Topmate SQL queries",
    "common_issues": {
        "slow_queries": {
            "symptoms": [
                "Query takes longer than expected",
                "Timeout errors",
                "High CPU usage",
            ],
            "solutions": [
                "Check if proper indexes exist on filtered columns",
                "Use EXPLAIN ANALYZE to identify bottlenecks",
                "Consider breaking complex queries into smaller steps",
                "Verify statistics are up to date with ANALYZE TABLE",
                "Add indexes on frequently filtered columns (created, status, expert_id)",
            ],
        },
        "incorrect_results": {
            "symptoms": [
                "Wrong row counts",
                "Unexpected null values",
                "Missing data",
            ],
            "solutions": [
                "Check JOIN conditions - ensure proper ON clauses",
                "Verify date range filters include boundary conditions",
                "Use INNER vs LEFT JOIN appropriately",
                "Handle NULL values explicitly with COALESCE",
                "Filter out test data (testing = false)",
            ],
        },
        "complex_aggregations": {
            "symptoms": [
                "Aggregation results don't match expectations",
                "GROUP BY errors",
            ],
            "solutions": [
                "Ensure all non-aggregated columns are in GROUP BY",
                "Use window functions for running totals and rankings",
                "Consider using HAVING for aggregate filtering instead of WHERE",
                "Break complex aggregations into CTEs for clarity",
            ],
        },
        "gmv_calculations": {
            "symptoms": [
                "GMV numbers don't match dashboard",
                "Missing bookings in reports",
                "Duplicate counts",
            ],
            "solutions": [
                "Always filter by status = 'completed' for GMV",
                "Exclude test bookings with testing = false",
                "Use 'price' column for GMV (not expert_earnings)",
                "Check timezone handling - use UTC for date filters",
                "Verify currency field for multi-currency calculations",
            ],
        },
        "user_metrics": {
            "symptoms": [
                "User counts inflated",
                "Cohort analysis incorrect",
                "Retention metrics wrong",
            ],
            "solutions": [
                "Filter out staff/admin users (is_staff = false)",
                "Use created vs date_joined appropriately",
                "Check is_active status for active user counts",
                "Use first booking date for cohort assignment, not registration",
            ],
        },
    },
    "best_practices": [
        "Always use created (not created_time) for date filtering on bookings",
        "Include testing = false to exclude test data",
        "Use DATE_TRUNC for monthly/weekly aggregations",
        "Join on integer IDs, not emails or usernames",
        "Use DISTINCT when joining multiple tables to avoid duplicates",
        "Consider timezone when comparing dates (database stores UTC)",
    ],
}
