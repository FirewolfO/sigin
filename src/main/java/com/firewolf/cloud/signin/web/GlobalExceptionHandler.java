package com.firewolf.cloud.signin.web;

import com.firewolf.cloud.signin.account.DomainException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(DomainException.class)
    ResponseEntity<ApiResponse<Void>> handleDomain(DomainException exception, HttpServletRequest request) {
        return ResponseEntity.status(exception.getStatus())
                .body(ApiResponse.error(request, exception.getCode(), exception.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException exception,
                                                       HttpServletRequest request) {
        FieldError first = exception.getBindingResult().getFieldErrors().stream().findFirst().orElse(null);
        String message = first == null ? "请求参数无效" : first.getDefaultMessage();
        return ResponseEntity.badRequest().body(ApiResponse.error(request, "INVALID_ARGUMENT", message));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ApiResponse<Void>> handleUnreadable(HttpMessageNotReadableException exception,
                                                       HttpServletRequest request) {
        return ResponseEntity.badRequest().body(ApiResponse.error(request, "INVALID_ARGUMENT", "请求数据格式错误"));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    ResponseEntity<ApiResponse<Void>> handleConflict(DataIntegrityViolationException exception,
                                                     HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiResponse.error(request, "CONFLICT", "账号、邮箱或手机号已被使用"));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiResponse<Void>> handleUnexpected(Exception exception, HttpServletRequest request) {
        Object requestId = request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE);
        log.error("Request {} failed", requestId, exception);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error(request, "INTERNAL_ERROR", "服务器处理请求失败"));
    }
}
