package com.firewolf.cloud.signin.account;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Pattern;

@Component
public class AccountNormalizer {

    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z][A-Za-z0-9_.-]{2,31}$");
    private static final Pattern EMAIL = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    private static final Pattern PHONE = Pattern.compile("^\\+[1-9]\\d{7,14}$");

    public String username(String value) {
        String normalized = required(value, "账号不能为空");
        if (!USERNAME.matcher(normalized).matches()) {
            throw DomainException.invalid("账号需为 3 到 32 位，并以字母开头，只能包含字母、数字、点、下划线或短横线");
        }
        return normalized.toLowerCase(Locale.ROOT);
    }

    public String email(String value) {
        String normalized = optional(value);
        if (normalized == null) {
            return null;
        }
        normalized = normalized.toLowerCase(Locale.ROOT);
        if (normalized.length() > 254 || !EMAIL.matcher(normalized).matches()) {
            throw DomainException.invalid("邮箱格式无效");
        }
        return normalized;
    }

    public String phone(String value) {
        String normalized = optional(value);
        if (normalized == null) {
            return null;
        }
        normalized = normalized.replaceAll("[\\s()-]", "");
        if (normalized.startsWith("00")) {
            normalized = "+" + normalized.substring(2);
        }
        if (!PHONE.matcher(normalized).matches()) {
            throw DomainException.invalid("手机号需使用包含国家代码的 E.164 格式，例如 +8613800138000");
        }
        return normalized;
    }

    public String displayName(String value, String fallback) {
        String normalized = optional(value);
        if (normalized == null) {
            normalized = fallback;
        }
        if (normalized.length() > 64) {
            throw DomainException.invalid("显示名称不能超过 64 个字符");
        }
        return normalized;
    }

    public String avatarUrl(String value) {
        String normalized = optional(value);
        if (normalized == null) {
            return null;
        }
        if (normalized.length() > 1000) {
            throw DomainException.invalid("头像地址不能超过 1000 个字符");
        }
        try {
            URI uri = new URI(normalized);
            if (uri.getHost() == null || !("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))) {
                throw DomainException.invalid("头像地址必须是有效的 HTTP 或 HTTPS URL");
            }
        } catch (URISyntaxException exception) {
            throw DomainException.invalid("头像地址必须是有效的 HTTP 或 HTTPS URL");
        }
        return normalized;
    }

    public LoginIdentifier loginIdentifier(String value) {
        String raw = required(value, "账号、手机号或邮箱不能为空");
        String username = raw.toLowerCase(Locale.ROOT);
        String email = raw.toLowerCase(Locale.ROOT);
        String phone = raw.replaceAll("[\\s()-]", "");
        if (phone.startsWith("00")) {
            phone = "+" + phone.substring(2);
        }
        return new LoginIdentifier(username, email, phone);
    }

    private String required(String value, String message) {
        String normalized = optional(value);
        if (normalized == null) {
            throw DomainException.invalid(message);
        }
        return normalized;
    }

    private String optional(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isEmpty() ? null : normalized;
    }

    public record LoginIdentifier(String username, String email, String phone) {
    }
}
