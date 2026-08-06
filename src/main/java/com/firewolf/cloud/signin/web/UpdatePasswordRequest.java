package com.firewolf.cloud.signin.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdatePasswordRequest(
        @NotBlank(message = "请输入当前密码")
        @Size(max = 72, message = "当前密码长度不能超过 72 个字符")
        String currentPassword,

        @NotBlank(message = "请输入新密码")
        @Size(min = 8, max = 72, message = "新密码长度必须为 8 到 72 个字符")
        String newPassword
) {
}
