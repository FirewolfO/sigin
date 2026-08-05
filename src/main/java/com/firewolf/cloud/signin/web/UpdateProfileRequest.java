package com.firewolf.cloud.signin.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UpdateProfileRequest(
        @NotBlank(message = "请输入显示名称")
        @Size(max = 64, message = "显示名称不能超过 64 个字符")
        String displayName,

        @Email(message = "邮箱格式无效")
        @Size(max = 254, message = "邮箱不能超过 254 个字符")
        String email,

        @Pattern(regexp = "^$|^\\+[1-9]\\d{7,14}$", message = "手机号需使用 E.164 格式")
        String phone,

        @Size(max = 1000, message = "头像地址不能超过 1000 个字符")
        String avatarUrl
) {
}
