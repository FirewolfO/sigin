package com.firewolf.cloud.signin.verification;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "login_verification_codes")
public class LoginVerificationCode {

    @Id
    private UUID id;

    @Column(name = "account_id", nullable = false)
    private UUID accountId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private VerificationChannel channel;

    @Column(name = "code_hash", nullable = false, length = 100)
    private String codeHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Version
    @Column(nullable = false)
    private long version;

    protected LoginVerificationCode() {
    }

    public LoginVerificationCode(UUID accountId, VerificationChannel channel,
                                 String codeHash, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.accountId = accountId;
        this.channel = channel;
        this.codeHash = codeHash;
        this.expiresAt = expiresAt;
    }

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
    }

    public void consume() {
        if (consumedAt == null) {
            consumedAt = Instant.now();
        }
    }

    public void recordFailedAttempt(int maxAttempts) {
        failedAttempts++;
        if (failedAttempts >= maxAttempts) {
            consume();
        }
    }

    public boolean isExpired() {
        return !expiresAt.isAfter(Instant.now());
    }

    public String getCodeHash() {
        return codeHash;
    }
}
