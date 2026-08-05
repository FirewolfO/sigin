package com.firewolf.cloud.signin.security;

import com.firewolf.cloud.signin.account.Account;
import com.firewolf.cloud.signin.account.AccountService;
import com.firewolf.cloud.signin.account.AccountStatus;
import com.firewolf.cloud.signin.account.DomainException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AccountUserDetailsService implements UserDetailsService {

    private final AccountService accountService;

    public AccountUserDetailsService(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            Account account = accountService.getByUsername(username);
            return User.withUsername(account.getUsername())
                    .password(account.getPasswordHash())
                    .roles("USER")
                    .disabled(account.getStatus() != AccountStatus.ACTIVE)
                    .build();
        } catch (DomainException exception) {
            throw new UsernameNotFoundException("account not found");
        }
    }
}
