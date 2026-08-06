package com.firewolf.cloud.signin.web;

import com.firewolf.cloud.signin.credential.ApiCredentialService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/account")
public class ApiCredentialController {

    private final ApiCredentialService credentialService;

    public ApiCredentialController(ApiCredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @GetMapping("/api-credentials")
    public ApiResponse<List<ApiCredentialView>> list(Authentication authentication, HttpServletRequest request) {
        List<ApiCredentialView> credentials = credentialService.list(authentication.getName()).stream()
                .map(ApiCredentialView::from)
                .toList();
        return ApiResponse.ok(request, credentials);
    }

    @PostMapping("/api-credentials")
    public ApiResponse<ApiCredentialView> create(Authentication authentication,
                                                 @Valid @RequestBody CreateApiCredentialRequest body,
                                                 HttpServletRequest request) {
        ApiCredentialService.GeneratedCredential generated = credentialService.create(authentication.getName(), body.name());
        return ApiResponse.created(request, ApiCredentialView.created(generated.credential(), generated.secretKey()));
    }

    @DeleteMapping("/api-credentials/{id}")
    public ApiResponse<Map<String, Boolean>> delete(Authentication authentication,
                                                    @PathVariable UUID id,
                                                    HttpServletRequest request) {
        credentialService.delete(authentication.getName(), id);
        return ApiResponse.ok(request, Map.of("deleted", true));
    }

}
