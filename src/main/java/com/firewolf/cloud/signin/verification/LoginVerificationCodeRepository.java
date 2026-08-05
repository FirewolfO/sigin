package com.firewolf.cloud.signin.verification;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface LoginVerificationCodeRepository extends JpaRepository<LoginVerificationCode, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    List<LoginVerificationCode> findAllByAccountIdAndChannelAndConsumedAtIsNull(
            UUID accountId, VerificationChannel channel);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<LoginVerificationCode> findFirstByAccountIdAndChannelAndConsumedAtIsNullOrderByCreatedAtDesc(
            UUID accountId, VerificationChannel channel);
}
