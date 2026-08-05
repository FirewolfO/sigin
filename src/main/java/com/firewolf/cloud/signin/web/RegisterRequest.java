package com.firewolf.cloud.signin.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "请输入账号")
        @Pattern(regexp = "^[A-Za-z][A-Za-z0-9_.-]{2,31}$", message = "账号格式无效")
        String username,

        @NotBlank(message = "请输入密码")
        @Size(min = 8, max = 72, message = "密码长度必须为 8 到 72 个字符")
        String password,

        @Size(max = 64, message = "显示名称不能超过 64 个字符")
        String displayName,

        @Email(message = "邮箱格式无效")
        @Size(max = 254, message = "邮箱不能超过 254 个字符")
        String email,

        @Pattern(regexp = "^$|^\\+[1-9]\\d{7,14}$", message = "手机号需使用 E.164 格式")
        String phone
) {
}
