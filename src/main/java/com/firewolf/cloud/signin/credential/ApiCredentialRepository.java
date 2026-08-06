package com.firewolf.cloud.signin.credential;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ApiCredentialRepository extends JpaRepository<ApiCredential, UUID> {

    List<ApiCredential> findAllByAccountIdOrderByCreatedAtDesc(UUID accountId);

    long countByAccountId(UUID accountId);

    Optional<ApiCredential> findByIdAndAccountId(UUID id, UUID accountId);

    @EntityGraph(attributePaths = "account")
    Optional<ApiCredential> findByAccessKey(String accessKey);
}
