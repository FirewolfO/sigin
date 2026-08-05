package com.firewolf.cloud.signin.web;

import com.firewolf.cloud.signin.verification.VerificationChannel;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record VerificationCodeLoginRequest(
        @NotNull(message = "请选择验证码类型")
        VerificationChannel channel,

        @NotBlank(message = "请输入手机号或邮箱")
        @Size(max = 254, message = "登录标识过长")
        String identifier,

        @NotBlank(message = "请输入验证码")
        @Pattern(regexp = "^\\d{6}$", message = "验证码必须为 6 位数字")
        String code
) {
}
