package com.firewolf.cloud.signin.verification;

import com.firewolf.cloud.signin.account.DomainException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.http.HttpClient;
import java.time.Duration;

@Component
public class VerificationCodeDelivery {

    private final VerificationCodeProperties properties;
    private final RestClient restClient;

    public VerificationCodeDelivery(VerificationCodeProperties properties) {
        this.properties = properties;
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(Duration.ofSeconds(5));
        this.restClient = RestClient.builder().requestFactory(requestFactory).build();
    }

    public void ensureAvailable() {
        if (!properties.isExposeInResponse() && properties.getDeliveryWebhook().isBlank()) {
            throw DomainException.serviceUnavailable("验证码发送服务未配置");
        }
    }

    public void deliver(VerificationCodeService.IssuedCode issuedCode) {
        if (!issuedCode.deliver() || properties.getDeliveryWebhook().isBlank()) {
            return;
        }
        try {
            RestClient.RequestBodySpec request = restClient.post()
                    .uri(properties.getDeliveryWebhook())
                    .contentType(MediaType.APPLICATION_JSON);
            if (!properties.getDeliveryToken().isBlank()) {
                request.header(HttpHeaders.AUTHORIZATION, "Bearer " + properties.getDeliveryToken());
            }
            request.body(new DeliveryRequest(
                            issuedCode.channel(), issuedCode.destination(), issuedCode.code(),
                            "LOGIN", properties.getTtl().toSeconds()))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException exception) {
            throw DomainException.serviceUnavailable("验证码发送失败，请稍后再试");
        }
    }

    private record DeliveryRequest(VerificationChannel channel, String destination,
                                   String code, String purpose, long expiresInSeconds) {
    }
}
