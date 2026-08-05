package com.firewolf.cloud.signin.account;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface AccountRepository extends JpaRepository<Account, UUID> {

    Optional<Account> findByUsernameNormalized(String usernameNormalized);

    Optional<Account> findByEmailNormalized(String emailNormalized);

    Optional<Account> findByPhoneNormalized(String phoneNormalized);

    boolean existsByUsernameNormalized(String usernameNormalized);

    boolean existsByEmailNormalized(String emailNormalized);

    boolean existsByPhoneNormalized(String phoneNormalized);

    boolean existsByEmailNormalizedAndIdNot(String emailNormalized, UUID id);

    boolean existsByPhoneNormalizedAndIdNot(String phoneNormalized, UUID id);
}
