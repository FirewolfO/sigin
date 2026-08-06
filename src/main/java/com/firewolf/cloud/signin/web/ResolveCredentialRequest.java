package com.firewolf.cloud.signin.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResolveCredentialRequest(
        @NotBlank(message = "Access Key 不能为空")
        @Size(max = 64, message = "Access Key 格式无效")
        String accessKey) {
}
