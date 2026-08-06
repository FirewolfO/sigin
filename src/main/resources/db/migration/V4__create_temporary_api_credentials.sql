CREATE TABLE temporary_api_credentials (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL,
    access_key VARCHAR(64) NOT NULL,
    secret_key_encrypted VARCHAR(1000) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT fk_temporary_api_credentials_account
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX uk_temporary_api_credentials_access_key
    ON temporary_api_credentials (access_key);
CREATE INDEX idx_temporary_api_credentials_expires_at
    ON temporary_api_credentials (expires_at);
