ALTER TABLE user ADD COLUMN active_family_id INTEGER;
ALTER TABLE user ADD COLUMN preferred_household TEXT;
ALTER TABLE user ADD COLUMN is_support_agent INTEGER NOT NULL DEFAULT 0;
