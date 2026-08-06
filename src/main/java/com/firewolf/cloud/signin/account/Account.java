package com.firewolf.cloud.signin.account;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "accounts")
public class Account {

    @Id
    private UUID id;

    @Column(nullable = false, length = 32)
    private String username;

    @Column(name = "username_normalized", nullable = false, length = 32, unique = true)
    private String usernameNormalized;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @Column(name = "display_name", nullable = false, length = 64)
    private String displayName;

    @Column(length = 254)
    private String email;

    @Column(name = "email_normalized", length = 254, unique = true)
    private String emailNormalized;

    @Column(length = 16)
    private String phone;

    @Column(name = "phone_normalized", length = 16, unique = true)
    private String phoneNormalized;

    @Column(name = "avatar_url", length = 1000)
    private String avatarUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AccountStatus status;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "programming_access_enabled", nullable = false)
    private boolean programmingAccessEnabled;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    @Column(nullable = false)
    private long version;

    protected Account() {
    }

    public Account(String username, String usernameNormalized, String passwordHash, String displayName,
                   String email, String emailNormalized, String phone, String phoneNormalized) {
        this.id = UUID.randomUUID();
        this.username = username;
        this.usernameNormalized = usernameNormalized;
        this.passwordHash = passwordHash;
        this.displayName = displayName;
        this.email = email;
        this.emailNormalized = emailNormalized;
        this.phone = phone;
        this.phoneNormalized = phoneNormalized;
        this.status = AccountStatus.ACTIVE;
    }

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
    }

    public void updateProfile(String displayName, String email, String emailNormalized,
                              String phone, String phoneNormalized, String avatarUrl) {
        this.displayName = displayName;
        this.email = email;
        this.emailNormalized = emailNormalized;
        this.phone = phone;
        this.phoneNormalized = phoneNormalized;
        this.avatarUrl = avatarUrl;
    }

    public void recordLogin() {
        this.lastLoginAt = Instant.now();
    }

    public void setProgrammingAccessEnabled(boolean enabled) {
        this.programmingAccessEnabled = enabled;
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getUsernameNormalized() {
        return usernameNormalized;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getEmail() {
        return email;
    }

    public String getPhone() {
        return phone;
    }

    public String getAvatarUrl() {
        return avatarUrl;
    }

    public AccountStatus getStatus() {
        return status;
    }

    public Instant getLastLoginAt() {
        return lastLoginAt;
    }

    public boolean isProgrammingAccessEnabled() {
        return programmingAccessEnabled;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
