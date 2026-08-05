package com.firewolf.cloud.signin.web;

import jakarta.servlet.http.HttpServletRequest;

public record ApiResponse<T>(String code, String message, T data, String requestId) {

    public static <T> ApiResponse<T> ok(HttpServletRequest request, T data) {
        return new ApiResponse<>("OK", "操作成功", data, requestId(request));
    }

    public static <T> ApiResponse<T> created(HttpServletRequest request, T data) {
        return new ApiResponse<>("OK", "创建成功", data, requestId(request));
    }

    public static ApiResponse<Void> error(HttpServletRequest request, String code, String message) {
        return new ApiResponse<>(code, message, null, requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE);
        return value instanceof String requestId ? requestId : "";
    }
}
