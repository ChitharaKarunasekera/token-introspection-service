package com.project.token_introspection_service.model;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.List;

/**
 * Internal representation of validated JWT claims.
 * This is NOT the HTTP response — it's what our service
 * works with internally after parsing the token.
 */
@Getter
@Builder
public class TokenClaims {

    private final String subject;
    private final String issuer;
    private final String clientId;
    private final List<String> scopes;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final String jwtId;
    private final String tokenType;
}
