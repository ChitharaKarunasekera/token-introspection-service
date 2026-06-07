package com.project.token_introspection_service.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.project.token_introspection_service.model.TokenClaims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Core token validation logic.
 *
 * Validates in this exact order — fail fast, fail safe:
 * 1. Parse         — is this a well-formed JWT?
 * 2. Algorithm     — is the algorithm on our whitelist? (prevents alg:none attack)
 * 3. Signature     — does the signature verify against the JWKS public key?
 * 4. Expiry        — is the token still within its validity window?
 * 5. Issuer        — did our expected IdP issue this token?
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenValidationService {

    private final JwksService jwksService;

    @Value("${app.idp.issuer}")
    private String expectedIssuer;

    @Value("${app.security.allowed-algorithms}")
    private String allowedAlgorithmsConfig;

    private static final long CLOCK_SKEW_SECONDS = 30;

    public Optional<TokenClaims> validate(String rawToken) {
        SignedJWT signedJWT = parse(rawToken);
        if (signedJWT == null) {
            return Optional.empty();
        }

        if (!isAlgorithmAllowed(signedJWT.getHeader())) {
            return Optional.empty();
        }

        if (!verifySignature(signedJWT)) {
            return Optional.empty();
        }

        return validateClaims(signedJWT);
    }

    private SignedJWT parse(String rawToken) {
        try {
            return SignedJWT.parse(rawToken);
        } catch (Exception e) {
            log.warn("Token parse failed — not a valid JWT structure");
            return null;
        }
    }

    private boolean isAlgorithmAllowed(JWSHeader header) {
        List<String> allowed = Arrays.asList(allowedAlgorithmsConfig.split(","));
        JWSAlgorithm algorithm = header.getAlgorithm();

        if (!allowed.contains(algorithm.getName())) {
            log.warn("Rejected token with disallowed algorithm: {}", algorithm.getName());
            return false;
        }

        return true;
    }

    /**
     * RS256 signature verification using the public key from JWKS.
     */
    private boolean verifySignature(SignedJWT signedJWT) {
        String kid = signedJWT.getHeader().getKeyID();

        if (kid == null) {
            log.warn("Token has no kid in header — cannot look up public key");
            return false;
        }

        Optional<RSAPublicKey> publicKey = jwksService.getPublicKey(kid);

        if (publicKey.isEmpty()) {
            log.warn("No public key found for kid '{}' — signature unverifiable", kid);
            return false;
        }

        try {
            RSASSAVerifier verifier = new RSASSAVerifier(publicKey.get());
            boolean valid = signedJWT.verify(verifier);

            if (!valid) {
                log.warn("Signature verification FAILED for kid '{}' — possible tampering", kid);
            }

            return valid;

        } catch (Exception e) {
            log.error("Exception during signature verification", e);
            return false;
        }
    }

    private Optional<TokenClaims> validateClaims(SignedJWT signedJWT) {
        try {
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Instant now = Instant.now();

            // Expiry check
            Date expiry = claims.getExpirationTime();
            if (expiry == null) {
                log.warn("Token has no expiry claim — rejecting");
                return Optional.empty();
            }

            if (now.isAfter(expiry.toInstant().plusSeconds(CLOCK_SKEW_SECONDS))) {
                log.warn("Token expired at {} (now is {})", expiry.toInstant(), now);
                return Optional.empty();
            }

            // Not-before check
            Date notBefore = claims.getNotBeforeTime();
            if (notBefore != null) {
                if (now.isBefore(notBefore.toInstant().minusSeconds(CLOCK_SKEW_SECONDS))) {
                    log.warn("Token not yet valid — nbf is {}", notBefore.toInstant());
                    return Optional.empty();
                }
            }

            // Issuer check
            String issuer = claims.getIssuer();
            if (!expectedIssuer.equals(issuer)) {
                log.warn("Issuer mismatch — expected '{}' but got '{}'", expectedIssuer, issuer);
                return Optional.empty();
            }

            // All checks passed — build TokenClaims
            String scopeString = (String) claims.getClaim("scope");
            List<String> scopes = scopeString != null
                    ? Arrays.asList(scopeString.split(" "))
                    : List.of();

            // azp = authorized party — Keycloak puts client_id here
            String clientId = (String) claims.getClaim("azp");

            return Optional.of(TokenClaims.builder()
                    .subject(claims.getSubject())
                    .issuer(claims.getIssuer())
                    .clientId(clientId)
                    .scopes(scopes)
                    .issuedAt(claims.getIssueTime() != null
                            ? claims.getIssueTime().toInstant() : null)
                    .expiresAt(expiry.toInstant())
                    .jwtId(claims.getJWTID())
                    .tokenType("Bearer")
                    .build());

        } catch (Exception e) {
            log.error("Exception during claims validation", e);
            return Optional.empty();
        }
    }
}
