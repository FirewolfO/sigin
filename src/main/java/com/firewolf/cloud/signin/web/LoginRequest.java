package com.firewolf.cloud.signin.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "请输入账号、手机号或邮箱")
        @Size(max = 254, message = "登录标识过长")
        String identifier,

        @NotBlank(message = "请输入密码")
        @Size(max = 72, message = "密码长度不能超过 72 个字符")
        String password
) {
}
