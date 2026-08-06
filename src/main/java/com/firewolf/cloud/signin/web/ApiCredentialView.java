package com.firewolf.cloud.signin.web;

import com.firewolf.cloud.signin.credential.ApiCredential;

import java.time.Instant;
import java.util.UUID;

public record ApiCredentialView(UUID id, String name, String accessKey, String secretKey, Instant createdAt) {

    private static final String MASKED_SECRET = "************************";

    public static ApiCredentialView from(ApiCredential credential) {
        return new ApiCredentialView(credential.getId(), credential.getName(), credential.getAccessKey(),
                MASKED_SECRET, credential.getCreatedAt());
    }

    public static ApiCredentialView created(ApiCredential credential, String secretKey) {
        return new ApiCredentialView(credential.getId(), credential.getName(), credential.getAccessKey(),
                secretKey, credential.getCreatedAt());
    }
}
