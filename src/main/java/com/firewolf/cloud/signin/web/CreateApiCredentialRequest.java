package com.firewolf.cloud.signin.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateApiCredentialRequest(
        @NotBlank(message = "请输入密钥名称")
        @Size(max = 64, message = "密钥名称不能超过 64 个字符")
        String name) {
}
