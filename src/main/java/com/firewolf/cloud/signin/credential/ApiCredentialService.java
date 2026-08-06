package com.firewolf.cloud.signin.credential;

import com.firewolf.cloud.signin.account.Account;
import com.firewolf.cloud.signin.account.AccountRepository;
import com.firewolf.cloud.signin.account.AccountStatus;
import com.firewolf.cloud.signin.account.DomainException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class ApiCredentialService {

    private static final int MAX_CREDENTIALS = 10;
    private final ApiCredentialRepository credentialRepository;
    private final AccountRepository accountRepository;
    private final SecretCipher secretCipher;
    private final Duration temporaryTtl;
    private final SecureRandom secureRandom = new SecureRandom();

    public ApiCredentialService(ApiCredentialRepository credentialRepository,
                                AccountRepository accountRepository,
                                SecretCipher secretCipher,
                                @Value("${signin.credentials.temporary-ttl:5m}") Duration temporaryTtl) {
        this.credentialRepository = credentialRepository;
        this.accountRepository = accountRepository;
        this.secretCipher = secretCipher;
        this.temporaryTtl = temporaryTtl;
    }

    @Transactional(readOnly = true)
    public List<ApiCredential> list(String username) {
        Account account = account(username);
        return credentialRepository.findAllByAccountIdOrderByCreatedAtDesc(account.getId());
    }

    @Transactional
    public GeneratedCredential create(String username, String requestedName) {
        Account account = account(username);
        String name = requestedName == null ? "" : requestedName.trim();
        if (name.isEmpty() || name.length() > 64) {
            throw DomainException.invalid("密钥名称长度必须为 1 到 64 个字符");
        }
        if (credentialRepository.countByAccountId(account.getId()) >= MAX_CREDENTIALS) {
            throw DomainException.conflict("每个账号最多创建 10 组 API 访问密钥");
        }
        String accessKey = randomToken("uak_", 18);
        String secretKey = randomToken("usk_", 32);
        ApiCredential credential = credentialRepository.save(
                new ApiCredential(account, name, accessKey, secretCipher.encrypt(secretKey)));
        return new GeneratedCredential(credential, secretKey);
    }

    @Transactional
    public void delete(String username, UUID credentialId) {
        Account account = account(username);
        ApiCredential credential = credentialRepository.findByIdAndAccountId(credentialId, account.getId())
                .orElseThrow(() -> DomainException.notFound("API 访问密钥不存在"));
        credentialRepository.delete(credential);
    }

    @Transactional(readOnly = true)
    public String secret(String username, UUID credentialId) {
        Account account = account(username);
        ApiCredential credential = credentialRepository.findByIdAndAccountId(credentialId, account.getId())
                .orElseThrow(() -> DomainException.notFound("API 访问密钥不存在"));
        return secretCipher.decrypt(credential.getSecretKeyEncrypted());
    }

    @Transactional(readOnly = true)
    public IssuedCredential resolve(String accessKey) {
        ApiCredential credential = credentialRepository.findByAccessKey(accessKey)
                .orElseThrow(DomainException::innerUnauthorized);
        Account account = credential.getAccount();
        if (account.getStatus() != AccountStatus.ACTIVE) {
            throw DomainException.innerUnauthorized();
        }
        return new IssuedCredential(account.getId(), credential.getAccessKey(),
                secretCipher.decrypt(credential.getSecretKeyEncrypted()), null);
    }

    @Transactional(readOnly = true)
    public IssuedCredential exchange(String username) {
        Account account = account(username);
        if (account.getStatus() != AccountStatus.ACTIVE) {
            throw DomainException.innerUnauthorized();
        }
        Instant expiresAt = Instant.now().plus(temporaryTtl);
        return new IssuedCredential(account.getId(), randomToken("utak_", 18),
                randomToken("utsk_", 32), expiresAt);
    }

    private Account account(String username) {
        return accountRepository.findByUsernameNormalized(username.toLowerCase(Locale.ROOT))
                .orElseThrow(DomainException::innerUnauthorized);
    }

    private String randomToken(String prefix, int size) {
        byte[] value = new byte[size];
        secureRandom.nextBytes(value);
        return prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    public record GeneratedCredential(ApiCredential credential, String secretKey) {
    }

    public record IssuedCredential(UUID accountId, String accessKey, String secretKey, Instant expiresAt) {
    }
}
