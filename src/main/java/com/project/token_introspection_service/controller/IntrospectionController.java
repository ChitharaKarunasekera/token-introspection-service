package com.project.token_introspection_service.controller;

import com.project.token_introspection_service.model.IntrospectionResponse;
import com.project.token_introspection_service.model.TokenClaims;
import com.project.token_introspection_service.service.TokenValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * RFC 7662 token introspection endpoint.
 * <p>
 * POST /introspect
 * Content-Type: application/x-www-form-urlencoded
 * Body: token=<access_token>
 * <p>
 */
@Slf4j
@RestController
@RequestMapping("/introspect")
@RequiredArgsConstructor
public class IntrospectionController {

    private final TokenValidationService tokenValidationService;

    /**
     * Introspects a token and returns its active status and claims.
     *
     * @param token         the raw JWT access token (required)
     * @param tokenTypeHint optional hint: "access_token" or "refresh_token"
     *                      We accept it per spec but don't use it —
     *                      we validate whatever token we receive.
     */
    @PostMapping(
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<IntrospectionResponse> introspect(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint
    ) {
        log.info("Introspection request received. token_type_hint={}",
                tokenTypeHint != null ? tokenTypeHint : "not provided");

        if (token == null || token.isBlank()) {
            log.warn("Introspection request received with empty token");
            return ResponseEntity.ok(IntrospectionResponse.inactive());
        }

        Optional<TokenClaims> validatedClaims = tokenValidationService.validate(token);

        if (validatedClaims.isEmpty()) {
            return ResponseEntity.ok(IntrospectionResponse.inactive());
        }

        TokenClaims claims = validatedClaims.get();

        IntrospectionResponse response = IntrospectionResponse.builder()
                .active(true)
                .subject(claims.getSubject())
                .issuer(claims.getIssuer())
                .clientId(claims.getClientId())
                .scope(String.join(" ", claims.getScopes()))
                .expiresAt(claims.getExpiresAt() != null
                        ? claims.getExpiresAt().getEpochSecond() : null)
                .issuedAt(claims.getIssuedAt() != null
                        ? claims.getIssuedAt().getEpochSecond() : null)
                .jwtId(claims.getJwtId())
                .tokenType(claims.getTokenType())
                .build();

        log.info("Token valid for subject='{}', scopes='{}'",
                claims.getSubject(),
                String.join(" ", claims.getScopes()));

        return ResponseEntity.ok(response);
    }
}
