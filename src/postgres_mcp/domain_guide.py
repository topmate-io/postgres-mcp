"""Curated per-domain schema + business-logic guide (LOOP-664 M3, spec §6)."""

from __future__ import annotations

ROUTING_TABLE = {
    "tm": "Topmate core: bookings, users, GMV, expert earnings.",
    "igdm": "Instagram Auto-DM V2: connections, automations, DM sequences/logs, subscriptions.",
    "fin_ledger": "Finance ledger: accounts, ledger_entries, holds, v1_snapshots, reconciliation.",
    "fin_payment": "Finance payments: payment_intents, subscriptions, settlements, v2_user_cutover.",
    "fin_payout": "Finance payouts: withdrawal_requests, bank_accounts, tds, fraud/KYC checks.",
}

MULTI_DOMAIN_GUIDE = {
    "tm": {
        "database": "topmate_db_prod",
        "purpose": "Topmate core monolith.",
        "gotchas": [
            "all_bookings_new (matview) uses created_time/expert_earning/book_currency; booking_booking uses created/expert_earnings/currency.",
            "Use get_topmate_schema_guide for full tm detail.",
        ],
    },
    "igdm": {
        "database": "instagram_auto_dm",
        "purpose": "Live Instagram Auto-DM V2 (~5.5k connections, ~8.1k automations).",
        "key_tables": {
            "instagram_connections": "root entity; join key user_id (String) — NOT deprecated topmate_user_id",
            "automations": "unified rule/sequence (is_active = rule on)",
            "dm_sequences": "per-(automation,user) funnel: opening->follow_gate->email->final->followup",
            "dm_logs": "outbound DM attempts",
            "instagram_subscriptions": "billing mirror; status='active' = paying (can drift from transactions-v2)",
            "agent_runs": "agentic path (when connections.ryl_brain_enabled=true)",
        },
        "gotchas": [
            "'active' is three things: connections.status='connected' (OAuth) != automations.is_active != subscription 'active'.",
            "brain vs rule are mutually exclusive per connection; brain-enabled -> look in agent_runs, not dm_sequences.",
            "ConnectionStatus: connected|disconnected|expired|error.",
        ],
    },
    "fin_ledger": {
        "database": "ledger_db",
        "purpose": "Double-entry ledger.",
        "key_tables": {
            "accounts": "available = balance - hold_amount; balance is denormalized (never SUM ledger_entries)",
            "ledger_entries": "immutable double-entry rows",
            "holds": "active->released|expired",
            "v1_snapshots": "frozen V1 cutover snapshot; expert_id is Integer",
        },
        "gotchas": [
            "Money is NUMERIC(20,6) MAJOR units (rupees/dollars), NOT paise.",
            "Negative balance is legitimate for account_type='gateway_settlement' and refund/reversal sources.",
        ],
    },
    "fin_payment": {
        "database": "payment_db",
        "purpose": "Payment orchestration + V1->V2 cutover state.",
        "key_tables": {
            "payment_intents": "PaymentState: pending|processing|paid|failed|cancelled|refunded|...",
            "v2_user_cutover": "per-user routing; expert_id Integer; check enabled/status/phase*",
            "subscriptions": "subscription lifecycle",
        },
        "gotchas": [
            "Lifetime earnings = v1_snapshots.v1_lifetime_earnings (frozen, ledger_db) + post-cutover ledger entries.",
            "shadow_* tables are parallel-run validation, NOT live routing state.",
        ],
    },
    "fin_payout": {
        "database": "payout_db",
        "purpose": "Withdrawals, bank accounts, TDS, fraud/KYC.",
        "key_tables": {
            "withdrawal_requests": "WithdrawalState: pending->verifying->approved|rejected|manual_review->processing->completed->reversed",
            "bank_accounts": "*_enc columns are AES ciphertext (unreadable); *_last4 are safe",
            "tds_records": "Section 194-O withholding",
            "verification_records": "KYC/Didit; decision_data is sensitive JSONB",
        },
        "gotchas": [
            "user_id/expert_id type drift: String(64) most tables, Integer in v1_snapshots/v2_user_cutover, UUID in suspicious_activity_reports.",
        ],
    },
}

CROSS_DOMAIN_NOTE = (
    "fin_ledger/fin_payment/fin_payout and igdm are separate RDS instances — no SQL joins across "
    "them. To correlate one creator, run one execute_sql per domain and stitch on user_id/expert_id "
    "in-model, minding the String/Integer/UUID type drift."
)


def build_schema_guide(enabled_domains: list[str]) -> dict:
    domains = {d: MULTI_DOMAIN_GUIDE[d] for d in enabled_domains if d in MULTI_DOMAIN_GUIDE}
    routing = {d: ROUTING_TABLE[d] for d in enabled_domains if d in ROUTING_TABLE}
    # The cross-domain "no SQL joins across RDS instances" caveat only makes sense when more
    # than one domain is reachable; when only tm is enabled it's noise, so drop it.
    cross_domain = CROSS_DOMAIN_NOTE if len(enabled_domains) > 1 else ""
    return {"routing": routing, "cross_domain": cross_domain, "domains": domains}
