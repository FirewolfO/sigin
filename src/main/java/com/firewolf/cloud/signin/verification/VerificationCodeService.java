package com.firewolf.cloud.signin.verification;

import com.firewolf.cloud.signin.account.Account;
import com.firewolf.cloud.signin.account.AccountNormalizer;
import com.firewolf.cloud.signin.account.AccountRepository;
import com.firewolf.cloud.signin.account.AccountStatus;
import com.firewolf.cloud.signin.account.DomainException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;

@Service
public class VerificationCodeService {

    private final SecureRandom secureRandom = new SecureRandom();
    private final AccountRepository accountRepository;
    private final AccountNormalizer normalizer;
    private final LoginVerificationCodeRepository codeRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationCodeProperties properties;

    public VerificationCodeService(AccountRepository accountRepository,
                                   AccountNormalizer normalizer,
                                   LoginVerificationCodeRepository codeRepository,
                                   PasswordEncoder passwordEncoder,
                                   VerificationCodeProperties properties) {
        this.accountRepository = accountRepository;
        this.normalizer = normalizer;
        this.codeRepository = codeRepository;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
    }

    @Transactional
    public IssuedCode issue(VerificationChannel channel, String identifier) {
        String destination = normalize(channel, identifier);
        String code = "%06d".formatted(secureRandom.nextInt(1_000_000));
        Optional<Account> account = findAccount(channel, destination)
                .filter(candidate -> candidate.getStatus() == AccountStatus.ACTIVE);

        if (account.isPresent()) {
            codeRepository.findAllByAccountIdAndChannelAndConsumedAtIsNull(account.get().getId(), channel)
                    .forEach(LoginVerificationCode::consume);
            codeRepository.save(new LoginVerificationCode(
                    account.get().getId(), channel, passwordEncoder.encode(code),
                    Instant.now().plus(properties.getTtl())));
        }
        return new IssuedCode(channel, destination, code, account.isPresent());
    }

    @Transactional(noRollbackFor = DomainException.class)
    public Account verify(VerificationChannel channel, String identifier, String code) {
        String destination = normalize(channel, identifier);
        Account account = findAccount(channel, destination)
                .filter(candidate -> candidate.getStatus() == AccountStatus.ACTIVE)
                .orElseThrow(DomainException::invalidVerificationCode);
        LoginVerificationCode challenge = codeRepository
                .findFirstByAccountIdAndChannelAndConsumedAtIsNullOrderByCreatedAtDesc(account.getId(), channel)
                .orElseThrow(DomainException::invalidVerificationCode);

        if (challenge.isExpired()) {
            challenge.consume();
            throw DomainException.invalidVerificationCode();
        }
        if (!passwordEncoder.matches(code, challenge.getCodeHash())) {
            challenge.recordFailedAttempt(properties.getMaxAttempts());
            throw DomainException.invalidVerificationCode();
        }
        challenge.consume();
        return account;
    }

    private Optional<Account> findAccount(VerificationChannel channel, String normalizedIdentifier) {
        return channel == VerificationChannel.EMAIL
                ? accountRepository.findByEmailNormalized(normalizedIdentifier)
                : accountRepository.findByPhoneNormalized(normalizedIdentifier);
    }

    private String normalize(VerificationChannel channel, String identifier) {
        String normalized = channel == VerificationChannel.EMAIL
                ? normalizer.email(identifier)
                : normalizer.phone(identifier);
        if (normalized == null) {
            throw DomainException.invalid(channel == VerificationChannel.EMAIL ? "请输入邮箱" : "请输入手机号");
        }
        return normalized;
    }

    public record IssuedCode(VerificationChannel channel, String destination, String code, boolean deliver) {
    }
}
