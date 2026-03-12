PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

BEGIN IMMEDIATE;

INSERT INTO workspace (tenant_id, owner_user_id, slug, name, compliance_mode)
VALUES
    (100, 1, 'north-platform', 'North Platform', 'strict'),
    (100, 2, 'north-payments', 'North Payments', 'moderate'),
    (200, 3, 'south-platform', 'South Platform', 'strict'),
    (200, 4, 'south-data', 'South Data', 'relaxed');

INSERT INTO project (tenant_id, workspace_id, lead_user_id, code, name, status)
VALUES
    (100, 1, 1, 'NRT', 'North Runtime', 'active'),
    (100, 1, 2, 'NED', 'North Edge', 'active'),
    (100, 2, 2, 'NPC', 'North Payments Core', 'active'),
    (200, 3, 3, 'SRT', 'South Runtime', 'active'),
    (200, 4, 4, 'SDL', 'South Data Lake', 'active');

INSERT INTO runbook (tenant_id, project_id, author_user_id, title, body, visibility)
VALUES
    (100, 1, 1, 'Restart API pods', 'Drain traffic before restart.', 'tenant'),
    (100, 3, 2, 'Reconcile failed payouts', 'Run reconciliation batch and verify ledger.', 'tenant'),
    (200, 4, 4, 'Backfill warehouse feed', 'Replay the previous six hours of warehouse events.', 'private');

INSERT INTO escalation_rule (tenant_id, workspace_id, owner_user_id, name, target_channel, severity_filter)
VALUES
    (100, 1, 1, 'Platform Sev1', '#north-platform-sev1', 'sev1'),
    (100, 2, 2, 'Payments Sev2', '#north-payments-alerts', 'sev2'),
    (200, 3, 3, 'South Runtime Sev1', '#south-runtime-sev1', 'sev1');

INSERT INTO incident (tenant_id, project_id, commander_user_id, summary, severity, status)
VALUES
    (100, 1, 1, 'API latency regression', 'sev1', 'active'),
    (100, 3, 2, 'Payout queue backlog', 'sev2', 'mitigated'),
    (200, 4, 4, 'Warehouse ingest delay', 'sev2', 'active');

INSERT INTO incident_note (tenant_id, incident_id, author_user_id, body, internal_only)
VALUES
    (100, 1, 1, 'Rolled back the last deployment while tracing pool saturation.', 0),
    (100, 1, 2, 'Need follow-up on TLS handshakes from edge nodes.', 1),
    (200, 3, 4, 'Backpressure cleared after increasing the batch worker count.', 0);

INSERT INTO deployment_window (tenant_id, project_id, approver_user_id, environment, starts_at, ends_at, status)
VALUES
    (100, 1, 1, 'production', '2026-03-12T19:00:00Z', '2026-03-12T20:30:00Z', 'approved'),
    (100, 3, 2, 'staging', '2026-03-13T08:00:00Z', '2026-03-13T10:00:00Z', 'pending'),
    (200, 4, 4, 'production', '2026-03-14T06:00:00Z', '2026-03-14T08:00:00Z', 'approved');

INSERT INTO on_call_subscription (tenant_id, project_id, subscriber_user_id, channel, escalation_level)
VALUES
    (100, 1, 1, 'pagerduty', 1),
    (100, 1, 2, 'slack', 2),
    (100, 3, 2, 'sms', 1),
    (200, 4, 4, 'pagerduty', 1);

INSERT INTO time_entry (tenant_id, incident_id, user_id, minutes, work_date, note)
VALUES
    (100, 1, 1, 90, '2026-03-12', 'Traffic rollback and baseline verification'),
    (100, 2, 2, 45, '2026-03-12', 'Queue tuning and payout replay'),
    (200, 3, 4, 75, '2026-03-12', 'Warehouse worker tuning');

INSERT INTO audit_export (tenant_id, requested_by_user_id, format, status)
VALUES
    (100, 1, 'csv', 'queued'),
    (100, 2, 'json', 'ready'),
    (200, 4, 'parquet', 'processing');

COMMIT;
ANALYZE;
