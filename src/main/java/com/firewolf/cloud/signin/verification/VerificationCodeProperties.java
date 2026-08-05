package com.firewolf.cloud.signin.verification;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix = "signin.verification-code")
public class VerificationCodeProperties {

    private Duration ttl = Duration.ofMinutes(5);
    private Duration resendInterval = Duration.ofSeconds(60);
    private int maxAttempts = 5;
    private boolean exposeInResponse;
    private String deliveryWebhook = "";
    private String deliveryToken = "";

    public Duration getTtl() {
        return ttl;
    }

    public void setTtl(Duration ttl) {
        this.ttl = ttl;
    }

    public Duration getResendInterval() {
        return resendInterval;
    }

    public void setResendInterval(Duration resendInterval) {
        this.resendInterval = resendInterval;
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public void setMaxAttempts(int maxAttempts) {
        this.maxAttempts = maxAttempts;
    }

    public boolean isExposeInResponse() {
        return exposeInResponse;
    }

    public void setExposeInResponse(boolean exposeInResponse) {
        this.exposeInResponse = exposeInResponse;
    }

    public String getDeliveryWebhook() {
        return deliveryWebhook;
    }

    public void setDeliveryWebhook(String deliveryWebhook) {
        this.deliveryWebhook = deliveryWebhook;
    }

    public String getDeliveryToken() {
        return deliveryToken;
    }

    public void setDeliveryToken(String deliveryToken) {
        this.deliveryToken = deliveryToken;
    }
}
