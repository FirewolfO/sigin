package com.firewolf.cloud.signin.web;

public record VerificationCodeIssuedView(
        long expiresInSeconds,
        long retryAfterSeconds,
        String developmentCode
) {
}
