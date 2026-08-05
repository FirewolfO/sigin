CREATE TABLE login_verification_codes (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL,
    channel VARCHAR(16) NOT NULL,
    code_hash VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_login_verification_codes_account
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    CONSTRAINT chk_login_verification_codes_channel CHECK (channel IN ('EMAIL', 'PHONE')),
    CONSTRAINT chk_login_verification_codes_failed_attempts CHECK (failed_attempts >= 0)
);

CREATE INDEX idx_login_verification_codes_lookup
    ON login_verification_codes (account_id, channel, created_at);
CREATE INDEX idx_login_verification_codes_expiry
    ON login_verification_codes (expires_at);
