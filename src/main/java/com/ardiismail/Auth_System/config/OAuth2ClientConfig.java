package com.ardiismail.Auth_System.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity
@Slf4j
public class OAuth2ClientConfig {

    private static final Logger log = LoggerFactory.getLogger(OAuth2ClientConfig.class);
    @Value("${app.host:localhost}")
    private String host;

    @Value("${app.port:8080}")
    private String port;

    @Value("${app.scheme:http}")
    private String scheme;

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private String keyId;

    public RSAPublicKey getPublicKey() {
        return this.publicKey;
    }

    public String getKeyId() {
        return this.keyId;
    }

    private String getBaseUrl() {
        if ("80".equals(port) && "http".equals(scheme) || "443".equals(port) && "https".equals(scheme)) {
            return scheme + "://" + host;
        } else {
            return scheme + "://" + host + ":" + port;
        }
    }

    @PostConstruct
    public void init() {
        try {
            // Generate RSA key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
            this.publicKey = (RSAPublicKey) keyPair.getPublic();
            this.keyId = UUID.randomUUID().toString();

            String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            log.info("Generated RSA key pair");
            log.info("Key ID: {}", keyId);
            log.info("Public Key (Base64): {}", encodedPublicKey);
            log.info("JWKS URL: {}/jwks", getBaseUrl());

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/public/**", "/error", "/jwks").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository())
                        .tokenEndpoint(token -> token
                                .accessTokenResponseClient(tokenResponseClient()))
                );

        return http.build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(mockpassClientRegistration());
    }

    private ClientRegistration mockpassClientRegistration() {
        return ClientRegistration.withRegistrationId("mockpass-idp")
                .clientId("cognito")
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(getBaseUrl() + "/login/oauth2/code/mockpass-idp")
                .scope("openid")
                .authorizationUri("https://5156-opengovsg-mockpass-hq06y0khfjx.ws-us118.gitpod.io/singpass/v2/authorize")
                .tokenUri("https://5156-opengovsg-mockpass-hq06y0khfjx.ws-us118.gitpod.io/singpass/v2/token")
                .jwkSetUri("https://5156-opengovsg-mockpass-hq06y0khfjx.ws-us118.gitpod.io/singpass/v2/.well-known/keys")
                .userNameAttributeName("id")
                .clientName("Mockpass IDP")
                .build();
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
        client.setRequestEntityConverter(new JwtAuthorizationCodeRequestConverter());
        return client;
    }

    // Custom converter for private_key_jwt client authentication
    private class JwtAuthorizationCodeRequestConverter extends OAuth2AuthorizationCodeGrantRequestEntityConverter {
        @Override
        protected MultiValueMap<String, String> createParameters(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.GRANT_TYPE, authorizationCodeGrantRequest.getGrantType().getValue());
            parameters.add(OAuth2ParameterNames.CODE,
                    authorizationCodeGrantRequest.getAuthorizationExchange().getAuthorizationResponse().getCode());

            String redirectUri = authorizationCodeGrantRequest.getAuthorizationExchange()
                    .getAuthorizationRequest().getRedirectUri();
            if (redirectUri != null) {
                parameters.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
            }

            ClientRegistration clientRegistration = authorizationCodeGrantRequest.getClientRegistration();

            // Add client_id parameter - this is required by some providers even with private_key_jwt
            parameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());

            try {
                // Generate JWT for client authentication
                String assertion = generateJwtAssertion(
                        clientRegistration.getClientId(),
                        clientRegistration.getProviderDetails().getTokenUri());

                parameters.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                parameters.add("client_assertion", assertion);

                // Log the complete request for debugging
                log.info("Token request parameters: {}", parameters);

            } catch (Exception e) {
                log.error("Error creating JWT assertion", e);
                throw new RuntimeException("Failed to create JWT assertion", e);
            }

            return parameters;
        }

        private String generateJwtAssertion(String clientId, String audience) throws Exception {
            Instant now = Instant.now();

            // Create JWT claims
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience(Collections.singletonList(audience))
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(java.util.Date.from(now))
                    .expirationTime(java.util.Date.from(now.plusSeconds(300))) // 5 minutes
                    .build();

            // Create JWT header with key ID
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(keyId)
                    .build();

            // Create and sign the JWT
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(new RSASSASigner(privateKey));

            return signedJWT.serialize();
        }
    }
}