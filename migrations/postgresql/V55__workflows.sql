CREATE TABLE workflows (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    trigger_events JSONB NOT NULL DEFAULT '[]'::jsonb,
    conditions JSONB NOT NULL DEFAULT '[]'::jsonb,
    steps JSONB NOT NULL,
    schedule_config JSONB,
    last_scheduled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX workflows_realm_name_uq ON workflows(realm_id, lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX workflows_event_idx ON workflows USING GIN(trigger_events) WHERE enabled AND deleted_at IS NULL;

CREATE TABLE workflow_executions (
    id UUID PRIMARY KEY,
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    trigger_event VARCHAR(120) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('queued','waiting','running','completed','failed','cancelled')),
    current_step INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX workflow_executions_due_idx ON workflow_executions(next_run_at) WHERE status IN ('queued','waiting');
CREATE INDEX workflow_executions_realm_idx ON workflow_executions(realm_id, created_at DESC);
CREATE UNIQUE INDEX workflow_executions_active_uq ON workflow_executions(workflow_id, user_id) WHERE status IN ('queued','waiting','running');
