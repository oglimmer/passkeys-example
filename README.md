# Passkeys (WebAuthn) Demo

Spring Boot application demonstrating WebAuthn (passkeys) authentication alongside traditional email/password login.

## Prerequisites

- Java 17+

## Running

```bash
./mvnw spring-boot:run
```

The app starts at [http://localhost:8080](http://localhost:8080).

## Authentication Flows

- **Password login** — Standard Spring Security form login
- **Passkey registration** — Authenticated users can register passkeys from the portal page
- **Passkey authentication** — Passwordless login using a registered passkey

## Tech Stack

- Spring Boot 3.4.3 (Web, Security, Data JPA, Thymeleaf)
- WebAuthn4J for passkey credential handling
- H2 file-based database (auto-created at `./data/passkeys`)
- Lombok

## WebAuthn Configuration

Relying party settings in `application.properties`:

| Property | Default |
|---|---|
| `app.webauthn.rp-id` | `localhost` |
| `app.webauthn.rp-name` | `Passkeys Demo` |
| `app.webauthn.allowed-origins` | `http://localhost:8080` |

Production deployments require HTTPS and matching origin/rp-id values.
