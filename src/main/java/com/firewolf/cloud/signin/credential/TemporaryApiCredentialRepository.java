package com.firewolf.cloud.signin.credential;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface TemporaryApiCredentialRepository extends JpaRepository<TemporaryApiCredential, UUID> {

    @EntityGraph(attributePaths = "account")
    Optional<TemporaryApiCredential> findByAccessKey(String accessKey);

    long deleteByExpiresAtLessThanEqual(Instant expiresAt);
}
