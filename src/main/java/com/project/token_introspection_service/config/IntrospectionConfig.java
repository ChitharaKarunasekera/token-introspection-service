package com.project.token_introspection_service.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

/**
 * Spring bean definitions for the introspection service.
 */
@Configuration
public class IntrospectionConfig {

    @Value("${app.jwks.cache-ttl-minutes}")
    private long cacheTtlMinutes;

    @Value("${app.jwks.cache-max-size}")
    private long cacheMaxSize;


    /**
     * Caffeine cache for JWKS public keys.
     * <p>
     * Key   = the JWKS URI string
     * Value = the parsed JWKSet (contains all public keys)
     */
    @Bean
    public Cache<String, JWKSet> jwksCache() {
        return Caffeine.newBuilder()
                .maximumSize(cacheMaxSize)
                .expireAfterWrite(cacheTtlMinutes, TimeUnit.MINUTES)
                .build();
    }

    /**
     * Pooled HTTP client for fetching JWKS from Keycloak.
     */
    @Bean
    public CloseableHttpClient httpClient() {
        PoolingHttpClientConnectionManager connectionManager =
                new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(20);
        connectionManager.setDefaultMaxPerRoute(10);

        return HttpClients.custom()
                .setConnectionManager(connectionManager)
                .build();
    }
}
