# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
mvn spring-boot:run        # Run the application (http://localhost:8080)
mvn clean compile           # Compile
mvn package                 # Build JAR
mvn clean install           # Full build
```

No tests exist yet. The project uses Maven with Spring Boot 3.4.3 and Java 17.

## Architecture

Spring Boot MVC application demonstrating WebAuthn (passkeys) authentication alongside traditional email/password login.

### Authentication Flows

1. **Password login**: Standard Spring Security form login → POST to `/login`
2. **Passkey registration**: Authenticated user on portal → fetches options from `/webauthn/register/options` → browser `navigator.credentials.create()` → POST attestation to `/webauthn/register`
3. **Passkey authentication**: Login page → fetches options from `/webauthn/authenticate/options` → browser `navigator.credentials.get()` → POST assertion to `/login/webauthn`

### Key Components

- **SecurityConfig** (`config/`): Configures Spring Security with both form login and WebAuthn. Defines public vs authenticated routes and WebAuthn relying party settings.
- **JpaPublicKeyCredentialUserEntityRepository** and **JpaUserCredentialRepository** (`service/`): Bridge Spring Security's WebAuthn API to JPA entities. These implement Spring Security interfaces for credential lookup/storage.
- **AppUserDetailsService** (`service/`): Standard `UserDetailsService` for password-based auth.
- **passkeys.js** (`static/js/`): Client-side WebAuthn API calls with Base64URL encoding/decoding utilities.

### Entity Model

`AppUser` (email, bcrypt password, 32-byte userHandle) → one-to-many → `PasskeyCredential` (credentialId, public key, signature count, attestation data, metadata).

### Database

H2 file-based database at `./data/passkeys` (user: `sa`, no password). Hibernate DDL mode is `update` (auto-creates schema).

### WebAuthn Config

Relying party settings are in `application.properties`: `app.webauthn.rp-id=localhost`, origins `http://localhost:8080`. Production requires HTTPS.
