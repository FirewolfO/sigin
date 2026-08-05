package com.firewolf.cloud.signin.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "请输入账号")
        @Size(max = 32, message = "账号长度不能超过 32 个字符")
        @Pattern(regexp = "^[A-Za-z][A-Za-z0-9_.-]{2,31}$", message = "账号格式无效")
        String identifier,

        @NotBlank(message = "请输入密码")
        @Size(max = 72, message = "密码长度不能超过 72 个字符")
        String password
) {
}
