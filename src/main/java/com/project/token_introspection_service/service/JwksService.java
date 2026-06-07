package com.project.token_introspection_service.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwksService {

    private final Cache<String, JWKSet> jwksCache;
    private final CloseableHttpClient httpClient;

    @Value("${app.idp.jwks-uri}")
    private String jwksUri;

    public Optional<RSAPublicKey> getPublicKey(String kid) {
        JWKSet jwkSet = jwksCache.getIfPresent(jwksUri);

        if (jwkSet == null) {
            log.info("JWKS cache miss — fetching from {}", jwksUri);
            jwkSet = fetchJwksFromIdp();

            if (jwkSet == null) {
                log.error("Failed to fetch JWKS from IdP");
                return Optional.empty();
            }

            jwksCache.put(jwksUri, jwkSet);
        }

        return findKeyById(jwkSet, kid)
                .or(() -> {
                    log.info("Unknown kid '{}' — re-fetching JWKS for possible key rotation", kid);
                    jwksCache.invalidate(jwksUri);
                    JWKSet freshSet = fetchJwksFromIdp();

                    if (freshSet == null) {
                        return Optional.empty();
                    }

                    jwksCache.put(jwksUri, freshSet);
                    return findKeyById(freshSet, kid);
                });
    }

    private Optional<RSAPublicKey> findKeyById(JWKSet jwkSet, String kid) {
        return Optional.ofNullable(jwkSet.getKeyByKeyId(kid))
                .filter(jwk -> jwk instanceof RSAKey)
                .map(jwk -> {
                    try {
                        return ((RSAKey) jwk).toRSAPublicKey();
                    } catch (Exception e) {
                        log.error("Failed to extract RSA public key for kid '{}'", kid, e);
                        return null;
                    }
                });
    }

    private JWKSet fetchJwksFromIdp() {
        try {
            HttpGet request = new HttpGet(jwksUri);

            return httpClient.execute(request, response -> {
                int statusCode = response.getCode();

                if (statusCode != 200) {
                    log.error("JWKS endpoint returned HTTP {}", statusCode);
                    return null;
                }

                try (InputStream body = response.getEntity().getContent()) {
                    try {
                        return JWKSet.load(body);
                    } catch (ParseException e) {
                        throw new RuntimeException(e);
                    }
                }
            });

        } catch (Exception e) {
            log.error("Exception while fetching JWKS from '{}'", jwksUri, e);
            return null;
        }
    }
}
