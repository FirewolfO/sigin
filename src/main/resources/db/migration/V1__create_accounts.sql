CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    username_normalized VARCHAR(32) NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    display_name VARCHAR(64) NOT NULL,
    email VARCHAR(254),
    email_normalized VARCHAR(254),
    phone VARCHAR(16),
    phone_normalized VARCHAR(16),
    avatar_url VARCHAR(1000),
    status VARCHAR(20) NOT NULL,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT chk_accounts_status CHECK (status IN ('ACTIVE', 'DISABLED'))
);

CREATE UNIQUE INDEX uk_accounts_username_normalized ON accounts (username_normalized);
CREATE UNIQUE INDEX uk_accounts_email_normalized ON accounts (email_normalized);
CREATE UNIQUE INDEX uk_accounts_phone_normalized ON accounts (phone_normalized);
CREATE INDEX idx_accounts_status ON accounts (status);
