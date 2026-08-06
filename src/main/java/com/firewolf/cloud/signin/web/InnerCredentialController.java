package com.firewolf.cloud.signin.web;

import com.firewolf.cloud.signin.account.DomainException;
import com.firewolf.cloud.signin.credential.ApiCredentialService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/inner/credentials")
public class InnerCredentialController {

    private final ApiCredentialService credentialService;

    public InnerCredentialController(ApiCredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @PostMapping("/resolve")
    public ApiResponse<IssuedCredentialView> resolve(@Valid @RequestBody ResolveCredentialRequest body,
                                                     HttpServletRequest request) {
        return ApiResponse.ok(request, IssuedCredentialView.from(credentialService.resolve(body.accessKey())));
    }

    @PostMapping("/exchange")
    public ApiResponse<IssuedCredentialView> exchange(Authentication authentication,
                                                      HttpServletRequest request) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw DomainException.innerUnauthorized();
        }
        return ApiResponse.ok(request,
                IssuedCredentialView.from(credentialService.exchange(authentication.getName())));
    }
}
