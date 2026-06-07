package com.project.token_introspection_service.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

/**
 * RFC 7662 compliant token introspection response.
 *
 * When active=false, all other fields are omitted (JsonInclude.NON_NULL).
 * This is required by spec — don't leak info about invalid tokens.
 */

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IntrospectionResponse {
    private final boolean active;

    @JsonProperty("sub")
    private final String subject;

    @JsonProperty("iss")
    private final String issuer;

    @JsonProperty("client_id")
    private final String clientId;

    private final String scope;

    @JsonProperty("exp")
    private final Long expiresAt;

    @JsonProperty("iat")
    private final Long issuedAt;

    @JsonProperty("jti")
    private final String jwtId;

    @JsonProperty("token_type")
    private final String tokenType;

    // Convenience factory — used when token is invalid or revoked
    public static IntrospectionResponse inactive() {
        return IntrospectionResponse.builder()
                .active(false)
                .build();
    }
}
