# Token Introspection & Validation Service

A microservice implementing **RFC 7662 Token Introspection** built with Java 17 and Spring Boot 3, developed as a hands-on exploration of token lifecycle management in OAuth 2.0 systems.

---

## Tech stack

| Technology | Version | Purpose |
|---|---|---|
| Java | 17 | Language |
| Spring Boot | 3.5 | Framework |
| Spring Security | 6.x | Endpoint protection |
| Nimbus JOSE + JWT | 9.37 | JWT parsing and RS256 verification |
| Caffeine | 3.1 | JWKS public key caching |
| Apache HttpClient 5 | 5.x | JWKS endpoint HTTP calls |
| Keycloak | 26.2 | Identity Provider (local Docker) |

---

## Standards implemented

| RFC | Title | What this service implements |
|---|---|---|
| RFC 7662 | Token Introspection | `POST /introspect` endpoint, `active` field, claim response shape |
| RFC 7519 | JSON Web Token (JWT) | JWT parsing, claim extraction |
| RFC 7517 | JSON Web Key (JWK) | JWKS fetching and public key resolution |
| RFC 7518 | JSON Web Algorithms | RS256 algorithm validation, algorithm whitelist |

---

## Running locally

### Prerequisites

- Java 17
- Maven 3.9+
- Docker

### 1. Start Keycloak

```bash
docker run -d --name keycloak -p 8180:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.2.5 start-dev
```

### 2. Configure Keycloak

- Create realm: `token-demo`
- Create client: `introspection-service` (confidential, direct access grants ON)
- Create user: `testuser` / `testpass`

### 3. Configure the service

Edit `src/main/resources/application.properties`:

```properties
app.client.secret=YOUR_CLIENT_SECRET_FROM_KEYCLOAK
```

### 4. Run

```bash
mvn spring-boot:run
```

Service starts on `http://localhost:8080`.

---

## API reference

### POST /introspect

Validates a token and returns its active status and claims.

**Request**

```
POST /introspect
Authorization: Basic cmVzb3VyY2Utc2VydmVyOnJzLXNlY3JldA==
Content-Type: application/x-www-form-urlencoded

token=<access_token>&token_type_hint=access_token
```

**Response — valid token**

```json
{
  "active": true,
  "sub": "4bc77335-e5c0-4ab7-9994-07e5da5495eb",
  "iss": "http://localhost:8180/realms/token-demo",
  "client_id": "introspection-service",
  "scope": "email profile",
  "exp": 1780849568,
  "iat": 1780849268,
  "jti": "c61d9aeb-8a91-4520-b167-9a24bf8043f0",
  "token_type": "Bearer"
}
```

**Response — invalid / expired / tampered token**

```json
{ "active": false }
```

### GET /actuator/health

```json
{ "status": "UP" }
```

No authentication required. Used by load balancers and monitoring systems.

---
