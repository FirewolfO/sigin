package com.firewolf.cloud.signin.web;

import com.firewolf.cloud.signin.credential.ApiCredentialService;

import java.time.Instant;
import java.util.UUID;

public record IssuedCredentialView(UUID accountId, String accessKey, String secretKey, Instant expiresAt) {

    public static IssuedCredentialView from(ApiCredentialService.IssuedCredential credential) {
        return new IssuedCredentialView(credential.accountId(), credential.accessKey(),
                credential.secretKey(), credential.expiresAt());
    }
}
