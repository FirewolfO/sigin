package com.firewolf.cloud.signin.web;

import com.firewolf.cloud.signin.account.Account;

import java.time.Instant;
import java.util.UUID;

public record UserView(
        UUID id,
        String username,
        String displayName,
        String email,
        String phone,
        String avatarUrl,
        Instant lastLoginAt,
        Instant createdAt,
        Instant updatedAt
) {
    public static UserView from(Account account) {
        return new UserView(
                account.getId(),
                account.getUsername(),
                account.getDisplayName(),
                account.getEmail(),
                account.getPhone(),
                account.getAvatarUrl(),
                account.getLastLoginAt(),
                account.getCreatedAt(),
                account.getUpdatedAt()
        );
    }
}
