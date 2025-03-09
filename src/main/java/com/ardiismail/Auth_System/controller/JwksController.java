package com.ardiismail.Auth_System.controller;

import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Map;

import com.ardiismail.Auth_System.config.OAuth2ClientConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class JwksController {

    private static final Logger log = LoggerFactory.getLogger(JwksController.class);
    private final OAuth2ClientConfig clientConfig;

    @Autowired
    public JwksController(OAuth2ClientConfig clientConfig) {
        this.clientConfig = clientConfig;
        log.info("JWKS Controller initialized");
    }

    @GetMapping("/jwks")
    public Map<String, Object> jwks() {
        log.info("JWKS endpoint called");

        RSAPublicKey publicKey = clientConfig.getPublicKey();
        String keyId = clientConfig.getKeyId();

        try {
            JWK jwk = new RSAKey.Builder(publicKey)
                    .keyID(keyId)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();

            Map<String, Object> jwkMap = jwk.toJSONObject();
            log.info("Returning JWKS with key ID: {}", keyId);
            return Collections.singletonMap("keys", Collections.singletonList(jwkMap));
        } catch (Exception e) {
            log.error("Error generating JWKS", e);
            throw new RuntimeException("Error generating JWKS", e);
        }
    }
}