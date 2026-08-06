package com.firewolf.cloud.signin.web;

import com.firewolf.cloud.signin.account.Account;
import com.firewolf.cloud.signin.account.AccountService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/account")
public class ProfileController {

    private final AccountService accountService;

    public ProfileController(AccountService accountService) {
        this.accountService = accountService;
    }

    @PutMapping("/profile")
    public ApiResponse<UserView> updateProfile(Authentication authentication,
                                               @Valid @RequestBody UpdateProfileRequest body,
                                               HttpServletRequest request) {
        Account account = accountService.updateProfile(authentication.getName(), new AccountService.ProfileCommand(
                body.displayName(), body.email(), body.phone(), body.avatarUrl()));
        return ApiResponse.ok(request, UserView.from(account));
    }

    @PutMapping("/password")
    public ApiResponse<Map<String, Boolean>> updatePassword(Authentication authentication,
                                                            @Valid @RequestBody UpdatePasswordRequest body,
                                                            HttpServletRequest request) {
        accountService.updatePassword(authentication.getName(),
                new AccountService.PasswordCommand(body.currentPassword(), body.newPassword()));
        return ApiResponse.ok(request, Map.of("updated", true));
    }
}
