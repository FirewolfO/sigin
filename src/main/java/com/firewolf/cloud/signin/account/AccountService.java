package com.firewolf.cloud.signin.account;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Service
public class AccountService {

    private final AccountRepository repository;
    private final AccountNormalizer normalizer;
    private final PasswordEncoder passwordEncoder;

    public AccountService(AccountRepository repository, AccountNormalizer normalizer, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.normalizer = normalizer;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public Account register(RegistrationCommand command) {
        String usernameNormalized = normalizer.username(command.username());
        String username = command.username().trim();
        String email = normalizer.email(command.email());
        String phone = normalizer.phone(command.phone());
        String displayName = normalizer.displayName(command.displayName(), username);

        if (repository.existsByUsernameNormalized(usernameNormalized)) {
            throw DomainException.conflict("该账号已被使用");
        }
        ensureEmailAvailable(email, null);
        ensurePhoneAvailable(phone, null);

        Account account = new Account(
                username,
                usernameNormalized,
                passwordEncoder.encode(command.password()),
                displayName,
                email,
                email,
                phone,
                phone
        );
        return repository.save(account);
    }

    @Transactional(readOnly = true)
    public Account getByUsername(String username) {
        return repository.findByUsernameNormalized(username.toLowerCase(Locale.ROOT))
                .orElseThrow(DomainException::unauthorized);
    }

    @Transactional
    public Account updateProfile(String username, ProfileCommand command) {
        Account account = getByUsername(username);
        String email = normalizer.email(command.email());
        String phone = normalizer.phone(command.phone());
        String displayName = normalizer.displayName(command.displayName(), account.getUsername());
        String avatarUrl = normalizer.avatarUrl(command.avatarUrl());

        ensureEmailAvailable(email, account.getId());
        ensurePhoneAvailable(phone, account.getId());
        account.updateProfile(displayName, email, email, phone, phone, avatarUrl);
        return account;
    }

    @Transactional
    public Account recordLogin(String username) {
        Account account = getByUsername(username);
        account.recordLogin();
        return account;
    }

    private void ensureEmailAvailable(String email, java.util.UUID accountId) {
        if (email == null) {
            return;
        }
        boolean exists = accountId == null
                ? repository.existsByEmailNormalized(email)
                : repository.existsByEmailNormalizedAndIdNot(email, accountId);
        if (exists) {
            throw DomainException.conflict("该邮箱已绑定其他账号");
        }
    }

    private void ensurePhoneAvailable(String phone, java.util.UUID accountId) {
        if (phone == null) {
            return;
        }
        boolean exists = accountId == null
                ? repository.existsByPhoneNormalized(phone)
                : repository.existsByPhoneNormalizedAndIdNot(phone, accountId);
        if (exists) {
            throw DomainException.conflict("该手机号已绑定其他账号");
        }
    }

    public record RegistrationCommand(String username, String password, String displayName, String email, String phone) {
    }

    public record ProfileCommand(String displayName, String email, String phone, String avatarUrl) {
    }
}
