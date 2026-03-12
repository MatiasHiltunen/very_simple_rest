-- Extend the built-in auth schema so login can emit the claims expected by ops_control.eon.
ALTER TABLE user ADD COLUMN tenant_id INTEGER;
CREATE INDEX idx_user_tenant_id ON user (tenant_id);
