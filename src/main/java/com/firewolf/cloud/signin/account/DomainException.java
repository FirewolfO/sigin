package com.firewolf.cloud.signin.account;

import org.springframework.http.HttpStatus;

public class DomainException extends RuntimeException {

    private final HttpStatus status;
    private final String code;

    public DomainException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public static DomainException invalid(String message) {
        return new DomainException(HttpStatus.BAD_REQUEST, "INVALID_ARGUMENT", message);
    }

    public static DomainException conflict(String message) {
        return new DomainException(HttpStatus.CONFLICT, "CONFLICT", message);
    }

    public static DomainException unauthorized() {
        return new DomainException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "账号或密码错误");
    }

    public static DomainException invalidVerificationCode() {
        return new DomainException(HttpStatus.UNAUTHORIZED, "INVALID_VERIFICATION_CODE", "手机号、邮箱或验证码错误");
    }

    public static DomainException tooManyRequests(String message) {
        return new DomainException(HttpStatus.TOO_MANY_REQUESTS, "TOO_MANY_REQUESTS", message);
    }

    public static DomainException serviceUnavailable(String message) {
        return new DomainException(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", message);
    }

    public static DomainException notFound(String message) {
        return new DomainException(HttpStatus.NOT_FOUND, "NOT_FOUND", message);
    }

    public static DomainException programmingAccessDisabled() {
        return new DomainException(HttpStatus.FORBIDDEN, "PROGRAMMING_ACCESS_DISABLED", "账号尚未开启编程访问");
    }

    public static DomainException innerUnauthorized() {
        return new DomainException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "内部调用认证失败");
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }
}
