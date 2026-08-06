package com.firewolf.cloud.signin.security;

import com.firewolf.cloud.signin.web.RequestIdFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class GatewayHmacFilter extends OncePerRequestFilter {

    private static final int MAX_BODY_SIZE = 1 << 20;
    private static final String CREDENTIAL_HEADER = "X-Gateway-Credential";
    private static final String SIGNATURE_HEADER = "X-Gateway-Signature";
    private static final String TIMESTAMP_HEADER = "X-Gateway-Timestamp";
    private static final String NONCE_HEADER = "X-Gateway-Nonce";
    private static final String PAYLOAD_HEADER = "X-Gateway-Content-SHA256";
    private final String accessKey;
    private final String secretKey;
    private final Duration signatureSkew;
    private final Map<String, Instant> nonces = new ConcurrentHashMap<>();

    public GatewayHmacFilter(String accessKey, String secretKey, Duration signatureSkew) {
        if (accessKey == null || accessKey.isBlank() || secretKey == null
                || secretKey.getBytes(StandardCharsets.UTF_8).length < 32 || signatureSkew.isNegative()
                || signatureSkew.isZero()) {
            throw new IllegalStateException("Gateway inner HMAC configuration is invalid");
        }
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.signatureSkew = signatureSkew;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/v1/inner/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        byte[] body = request.getInputStream().readNBytes(MAX_BODY_SIZE + 1);
        if (body.length > MAX_BODY_SIZE) {
            writeError(request, response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                    "PAYLOAD_TOO_LARGE", "内部请求体不能超过 1 MiB");
            return;
        }
        CachedBodyRequest wrapped = new CachedBodyRequest(request, body);
        if (!verify(wrapped, body)) {
            writeError(request, response, HttpServletResponse.SC_UNAUTHORIZED,
                    "UNAUTHORIZED", "内部调用认证失败");
            return;
        }
        filterChain.doFilter(wrapped, response);
    }

    private boolean verify(HttpServletRequest request, byte[] body) {
        try {
            String suppliedAccessKey = request.getHeader(CREDENTIAL_HEADER);
            String timestamp = request.getHeader(TIMESTAMP_HEADER);
            String nonce = request.getHeader(NONCE_HEADER);
            String suppliedPayloadHash = request.getHeader(PAYLOAD_HEADER);
            String suppliedSignature = request.getHeader(SIGNATURE_HEADER);
            if (!constantEquals(accessKey, suppliedAccessKey) || timestamp == null || nonce == null
                    || nonce.length() < 16 || nonce.length() > 128 || suppliedPayloadHash == null
                    || suppliedSignature == null || request.getQueryString() != null) {
                return false;
            }
            Instant requestTime = Instant.ofEpochSecond(Long.parseLong(timestamp));
            Instant now = Instant.now();
            if (requestTime.isBefore(now.minus(signatureSkew)) || requestTime.isAfter(now.plus(signatureSkew))) {
                return false;
            }
            String payloadHash = sha256(body);
            if (!constantEquals(payloadHash, suppliedPayloadHash.toLowerCase())) {
                return false;
            }
            String canonical = String.join("\n", request.getMethod().toUpperCase(), request.getRequestURI(), "",
                    timestamp, nonce, payloadHash);
            if (!constantEquals(hmac(canonical), suppliedSignature.toLowerCase())) {
                return false;
            }
            purgeExpiredNonces(now);
            return nonces.putIfAbsent(accessKey + ":" + nonce, requestTime.plus(signatureSkew)) == null;
        } catch (RuntimeException | GeneralSecurityException exception) {
            return false;
        }
    }

    private void purgeExpiredNonces(Instant now) {
        Iterator<Map.Entry<String, Instant>> iterator = nonces.entrySet().iterator();
        while (iterator.hasNext()) {
            if (!iterator.next().getValue().isAfter(now)) {
                iterator.remove();
            }
        }
    }

    private String sha256(byte[] body) throws GeneralSecurityException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
    }

    private String hmac(String canonical) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    private boolean constantEquals(String expected, String actual) {
        return actual != null && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private void writeError(HttpServletRequest request, HttpServletResponse response,
                            int status, String code, String message) throws IOException {
        Object requestId = request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE);
        String safeRequestId = requestId instanceof String value ? value : "";
        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write("{\"code\":\"" + code + "\",\"message\":\"" + message
                + "\",\"requestId\":\"" + safeRequestId + "\"}");
    }

    private static final class CachedBodyRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        private CachedBodyRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream input = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return input.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener readListener) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public int read() {
                    return input.read();
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }
    }
}
