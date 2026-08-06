package com.firewolf.cloud.signin;

import com.firewolf.cloud.signin.account.Account;
import com.firewolf.cloud.signin.account.AccountRepository;
import com.firewolf.cloud.signin.credential.ApiCredentialRepository;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import jakarta.servlet.http.Cookie;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private ApiCredentialRepository apiCredentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void clearAccounts() {
        apiCredentialRepository.deleteAll();
        accountRepository.deleteAll();
    }

    @Test
    void registerUpdateProfileAndLoginWithUsername() throws Exception {
        MockHttpSession registeredSession = register("alice", "Secret123!", "Alice");

        Account stored = accountRepository.findByUsernameNormalized("alice").orElseThrow();
        assertThat(stored.getPasswordHash()).isNotEqualTo("Secret123!");
        assertThat(passwordEncoder.matches("Secret123!", stored.getPasswordHash())).isTrue();

        CsrfValues csrf = csrfValues();
        mockMvc.perform(put("/api/v1/account/profile")
                        .session(registeredSession)
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"displayName":"Alice Cloud","email":"Alice@Example.com","phone":"+8613800138000","avatarUrl":"https://example.com/avatar.png"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.email").value("alice@example.com"))
                .andExpect(jsonPath("$.data.phone").value("+8613800138000"));

        loginAndReadProfile("alice", "Secret123!");
    }

    @Test
    void loginWithSingleUseCodesForEmailAndPhone() throws Exception {
        registerWithContacts("dana", "Dana@Example.com", "+8613900139000");

        String emailCode = requestVerificationCode("EMAIL", "DANA@EXAMPLE.COM");
        loginWithVerificationCode("EMAIL", "dana@example.com", emailCode);

        CsrfValues reusedCodeCsrf = csrfValues();
        mockMvc.perform(post("/api/v1/auth/code-login")
                        .cookie(reusedCodeCsrf.cookie())
                        .header("X-XSRF-TOKEN", reusedCodeCsrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"channel":"EMAIL","identifier":"dana@example.com","code":"%s"}
                                """.formatted(emailCode)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_VERIFICATION_CODE"));

        String phoneCode = requestVerificationCode("PHONE", "+86 139-0013-9000");
        loginWithVerificationCode("PHONE", "+8613900139000", phoneCode);

        CsrfValues passwordCsrf = csrfValues();
        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(passwordCsrf.cookie())
                        .header("X-XSRF-TOKEN", passwordCsrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"identifier":"dana@example.com","password":"Secret123!"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_ARGUMENT"));
    }

    @Test
    void rejectsDuplicateBindingsAndMissingCsrf() throws Exception {
        registerWithEmail("owner", "owner@example.com");
        register("second", "Secret123!", "Second");

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"third","password":"Secret123!","displayName":"Third","email":"owner@example.com"}
                                """))
                .andExpect(status().isForbidden());

        CsrfValues csrf = csrfValues();
        mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"third","password":"Secret123!","displayName":"Third","email":"owner@example.com"}
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("CONFLICT"));
    }

    @Test
    void rejectsInvalidCredentialsAndAnonymousProfileAccess() throws Exception {
        register("bob", "Secret123!", "Bob");

        CsrfValues csrf = csrfValues();
        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"identifier":"bob","password":"wrong-password"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("账号或密码错误"));

        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void exposesCsrfCookieAndInvalidatesSessionOnLogout() throws Exception {
        CsrfValues csrf = csrfValues();

        MockHttpSession session = register("carol", "Secret123!", "Carol");
        mockMvc.perform(post("/api/v1/auth/logout")
                        .session(session)
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.loggedOut").value(true));

        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void managesApiCredentialsAndProtectsInnerResolution() throws Exception {
        MockHttpSession session = register("developer", "Secret123!", "Developer");
        CsrfValues createCsrf = csrfValues();
        MvcResult created = mockMvc.perform(post("/api/v1/account/api-credentials")
                        .session(session)
                        .cookie(createCsrf.cookie())
                        .header("X-XSRF-TOKEN", createCsrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"本地开发\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessKey").value(org.hamcrest.Matchers.startsWith("uak_")))
                .andExpect(jsonPath("$.data.secretKey").value(org.hamcrest.Matchers.startsWith("usk_")))
                .andReturn();
        String credentialId = JsonPath.read(created.getResponse().getContentAsString(), "$.data.id");
        String accessKey = JsonPath.read(created.getResponse().getContentAsString(), "$.data.accessKey");
        String secretKey = JsonPath.read(created.getResponse().getContentAsString(), "$.data.secretKey");

        mockMvc.perform(get("/api/v1/account/api-credentials").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].secretKey").value("************************"));
        String resolveBody = "{\"accessKey\":\"" + accessKey + "\"}";
        mockMvc.perform(post("/api/v1/inner/credentials/resolve")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resolveBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
        mockMvc.perform(signedInnerPost("/api/v1/inner/credentials/resolve", resolveBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessKey").value(accessKey))
                .andExpect(jsonPath("$.data.secretKey").value(secretKey))
                .andExpect(jsonPath("$.data.expiresAt").doesNotExist());
        mockMvc.perform(signedInnerPost("/api/v1/inner/credentials/exchange", "{}").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessKey").value(org.hamcrest.Matchers.startsWith("utak_")))
                .andExpect(jsonPath("$.data.secretKey").value(org.hamcrest.Matchers.startsWith("utsk_")))
                .andExpect(jsonPath("$.data.expiresAt").isString());

        CsrfValues deleteCsrf = csrfValues();
        mockMvc.perform(delete("/api/v1/account/api-credentials/{id}", credentialId)
                        .session(session)
                        .cookie(deleteCsrf.cookie())
                        .header("X-XSRF-TOKEN", deleteCsrf.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.deleted").value(true));
    }

    private MockHttpSession register(String username, String password, String displayName) throws Exception {
        CsrfValues csrf = csrfValues();
        return (MockHttpSession) mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s","displayName":"%s"}
                                """.formatted(username, password, displayName)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.username").value(username))
                .andReturn().getRequest().getSession(false);
    }

    private void registerWithEmail(String username, String email) throws Exception {
        CsrfValues csrf = csrfValues();
        mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"Secret123!","displayName":"Owner","email":"%s"}
                                """.formatted(username, email)))
                .andExpect(status().isCreated());
    }

    private void registerWithContacts(String username, String email, String phone) throws Exception {
        CsrfValues csrf = csrfValues();
        mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"Secret123!","displayName":"Dana","email":"%s","phone":"%s"}
                                """.formatted(username, email, phone)))
                .andExpect(status().isCreated());
    }

    private String requestVerificationCode(String channel, String identifier) throws Exception {
        CsrfValues csrf = csrfValues();
        MvcResult result = mockMvc.perform(post("/api/v1/auth/verification-codes")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"channel":"%s","identifier":"%s"}
                                """.formatted(channel, identifier)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.expiresInSeconds").value(300))
                .andExpect(jsonPath("$.data.retryAfterSeconds").value(60))
                .andExpect(jsonPath("$.data.developmentCode").isString())
                .andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.data.developmentCode");
    }

    private void loginWithVerificationCode(String channel, String identifier, String code) throws Exception {
        CsrfValues csrf = csrfValues();
        mockMvc.perform(post("/api/v1/auth/code-login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"channel":"%s","identifier":"%s","code":"%s"}
                                """.formatted(channel, identifier, code)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("dana"));
    }

    private void loginAndReadProfile(String identifier, String password) throws Exception {
        CsrfValues csrf = csrfValues();
        MockHttpSession session = (MockHttpSession) mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"identifier":"%s","password":"%s"}
                                """.formatted(identifier, password)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("alice"))
                .andReturn().getRequest().getSession(false);

        mockMvc.perform(get("/api/v1/auth/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.displayName").value("Alice Cloud"));
    }

    private CsrfValues csrfValues() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/csrf"))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("XSRF-TOKEN"))
                .andExpect(jsonPath("$.data.headerName").value("X-XSRF-TOKEN"))
                .andReturn();
        Cookie cookie = result.getResponse().getCookie("XSRF-TOKEN");
        assertThat(cookie).isNotNull();
        return new CsrfValues(cookie, cookie.getValue());
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder signedInnerPost(
            String path, String body) throws Exception {
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        String payloadHash = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(body.getBytes(StandardCharsets.UTF_8)));
        String canonical = String.join("\n", "POST", path, "", timestamp, nonce, payloadHash);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"));
        String signature = HexFormat.of().formatHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        return post(path)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .header("X-Gateway-Credential", "gwak_gateway_test")
                .header("X-Gateway-Timestamp", timestamp)
                .header("X-Gateway-Nonce", nonce)
                .header("X-Gateway-Content-SHA256", payloadHash)
                .header("X-Gateway-Signature", signature);
    }

    private record CsrfValues(Cookie cookie, String token) {
    }
}
