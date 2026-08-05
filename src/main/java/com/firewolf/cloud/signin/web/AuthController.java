package com.firewolf.cloud.signin.web;

import com.firewolf.cloud.signin.account.Account;
import com.firewolf.cloud.signin.account.AccountService;
import com.firewolf.cloud.signin.account.AttemptLimiter;
import com.firewolf.cloud.signin.account.DomainException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Locale;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Duration LOGIN_WINDOW = Duration.ofMinutes(5);
    private static final Duration REGISTRATION_WINDOW = Duration.ofHours(1);

    private final AccountService accountService;
    private final AttemptLimiter attemptLimiter;
    private final AuthenticationManager authenticationManager;
    private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
    private final SecurityContextRepository securityContextRepository;

    public AuthController(AccountService accountService,
                          AttemptLimiter attemptLimiter,
                          AuthenticationManager authenticationManager,
                          SessionAuthenticationStrategy sessionAuthenticationStrategy,
                          SecurityContextRepository securityContextRepository) {
        this.accountService = accountService;
        this.attemptLimiter = attemptLimiter;
        this.authenticationManager = authenticationManager;
        this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
        this.securityContextRepository = securityContextRepository;
    }

    @GetMapping("/csrf")
    public ApiResponse<Map<String, String>> csrf(CsrfToken csrfToken, HttpServletRequest request) {
        return ApiResponse.ok(request, Map.of(
                "headerName", csrfToken.getHeaderName(),
                "parameterName", csrfToken.getParameterName()
        ));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserView>> register(@Valid @RequestBody RegisterRequest body,
                                                          HttpServletRequest request,
                                                          HttpServletResponse response) {
        String rateKey = "register:" + request.getRemoteAddr();
        attemptLimiter.check(rateKey, 10, REGISTRATION_WINDOW, "注册请求过于频繁，请稍后再试");
        attemptLimiter.record(rateKey, REGISTRATION_WINDOW);

        Account account = accountService.register(new AccountService.RegistrationCommand(
                body.username(), body.password(), body.displayName(), body.email(), body.phone()));
        Authentication authentication = authenticate(account.getUsername(), body.password(), request, response);
        Account current = accountService.recordLogin(authentication.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.created(request, UserView.from(current)));
    }

    @PostMapping("/login")
    public ApiResponse<UserView> login(@Valid @RequestBody LoginRequest body,
                                       HttpServletRequest request,
                                       HttpServletResponse response) {
        String rateKey = "login:" + request.getRemoteAddr() + ":"
                + body.identifier().trim().toLowerCase(Locale.ROOT);
        attemptLimiter.check(rateKey, 5, LOGIN_WINDOW, "登录失败次数过多，请稍后再试");
        try {
            Authentication authentication = authenticate(body.identifier(), body.password(), request, response);
            attemptLimiter.reset(rateKey);
            Account account = accountService.recordLogin(authentication.getName());
            return ApiResponse.ok(request, UserView.from(account));
        } catch (AuthenticationException exception) {
            attemptLimiter.record(rateKey, LOGIN_WINDOW);
            throw DomainException.unauthorized();
        }
    }

    @GetMapping("/me")
    public ApiResponse<UserView> me(Authentication authentication, HttpServletRequest request) {
        Account account = accountService.getByUsername(authentication.getName());
        return ApiResponse.ok(request, UserView.from(account));
    }

    @PostMapping("/logout")
    public ApiResponse<Map<String, Boolean>> logout(Authentication authentication,
                                                    HttpServletRequest request,
                                                    HttpServletResponse response) {
        new SecurityContextLogoutHandler().logout(request, response, authentication);
        return ApiResponse.ok(request, Map.of("loggedOut", true));
    }

    private Authentication authenticate(String identifier, String password,
                                        HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(identifier, password));
        sessionAuthenticationStrategy.onAuthentication(authentication, request, response);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        return authentication;
    }
}
