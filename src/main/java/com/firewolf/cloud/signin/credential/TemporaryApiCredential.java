package com.firewolf.cloud.signin.credential;

import com.firewolf.cloud.signin.account.Account;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "temporary_api_credentials")
public class TemporaryApiCredential {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    @Column(name = "access_key", nullable = false, length = 64, unique = true)
    private String accessKey;

    @Column(name = "secret_key_encrypted", nullable = false, length = 1000)
    private String secretKeyEncrypted;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected TemporaryApiCredential() {
    }

    public TemporaryApiCredential(Account account, String accessKey, String secretKeyEncrypted, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.account = account;
        this.accessKey = accessKey;
        this.secretKeyEncrypted = secretKeyEncrypted;
        this.expiresAt = expiresAt;
    }

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
    }

    public Account getAccount() {
        return account;
    }

    public String getAccessKey() {
        return accessKey;
    }

    public String getSecretKeyEncrypted() {
        return secretKeyEncrypted;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
