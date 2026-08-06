package com.firewolf.cloud.signin.credential;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class SecretCipher {

    private static final int NONCE_SIZE = 12;
    private static final int TAG_BITS = 128;
    private final SecretKeySpec key;
    private final SecureRandom secureRandom = new SecureRandom();

    public SecretCipher(@Value("${signin.credentials.encryption-key}") String masterKey) {
        if (masterKey == null || masterKey.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("SIGNIN_CREDENTIAL_ENCRYPTION_KEY must contain at least 32 bytes");
        }
        try {
            this.key = new SecretKeySpec(MessageDigest.getInstance("SHA-256")
                    .digest(masterKey.getBytes(StandardCharsets.UTF_8)), "AES");
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to initialize credential encryption", exception);
        }
    }

    public String encrypt(String plaintext) {
        try {
            byte[] nonce = new byte[NONCE_SIZE];
            secureRandom.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] payload = new byte[nonce.length + encrypted.length];
            System.arraycopy(nonce, 0, payload, 0, nonce.length);
            System.arraycopy(encrypted, 0, payload, nonce.length, encrypted.length);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to encrypt API credential", exception);
        }
    }

    public String decrypt(String encrypted) {
        try {
            byte[] payload = Base64.getUrlDecoder().decode(encrypted);
            if (payload.length <= NONCE_SIZE) {
                throw new GeneralSecurityException("invalid encrypted credential");
            }
            byte[] nonce = new byte[NONCE_SIZE];
            byte[] ciphertext = new byte[payload.length - NONCE_SIZE];
            System.arraycopy(payload, 0, nonce, 0, nonce.length);
            System.arraycopy(payload, nonce.length, ciphertext, 0, ciphertext.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalStateException("Unable to decrypt API credential", exception);
        }
    }
}
