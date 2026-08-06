ALTER TABLE accounts
    ADD COLUMN programming_access_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE api_credentials (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL,
    name VARCHAR(64) NOT NULL,
    access_key VARCHAR(64) NOT NULL,
    secret_key_encrypted VARCHAR(1000) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT fk_api_credentials_account
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX uk_api_credentials_access_key ON api_credentials (access_key);
CREATE INDEX idx_api_credentials_account_id ON api_credentials (account_id);
