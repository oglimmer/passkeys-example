# Integrating Passkeys (WebAuthn) into a Spring Boot Application

This guide covers what you need to do to add passkey-based registration and login to a Spring Boot web application using Spring Security's WebAuthn module.

## How It Works

Both registration and authentication follow the same three-leg pattern between Browser, Server, and Authenticator:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ REGISTRATION (Attestation)                                               │
│                                                                          │
│  Browser                     Server                    Authenticator     │
│    │                           │                            │            │
│    │  POST /webauthn/          │                            │            │
│    │  register/options         │                            │            │
│    │ ────────────────────────► │                            │            │
│    │                           │  generate challenge,       │            │
│    │                           │  build CreationOptions     │            │
│    │  ◄──────────────────────  │                            │            │
│    │  PublicKeyCredential      │                            │            │
│    │  CreationOptions (JSON)   │                            │            │
│    │                           │                            │            │
│    │  navigator.credentials.create(options)                 │            │
│    │ ──────────────────────────────────────────────────────► │            │
│    │                                                        │  create    │
│    │                                                        │  key pair, │
│    │                                                        │  sign      │
│    │  ◄──────────────────────────────────────────────────── │  challenge │
│    │  attestation response                                  │            │
│    │  (credentialId, publicKey, signedChallenge)             │            │
│    │                           │                            │            │
│    │  POST /webauthn/register  │                            │            │
│    │  (attestation response)   │                            │            │
│    │ ────────────────────────► │                            │            │
│    │                           │  verify signature,         │            │
│    │                           │  store public key          │            │
│    │  ◄──────────────────────  │                            │            │
│    │  success                  │                            │            │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│ AUTHENTICATION (Assertion)                                               │
│                                                                          │
│  Browser                     Server                    Authenticator     │
│    │                           │                            │            │
│    │  POST /webauthn/          │                            │            │
│    │  authenticate/options     │                            │            │
│    │ ────────────────────────► │                            │            │
│    │                           │  generate challenge,       │            │
│    │                           │  build RequestOptions      │            │
│    │  ◄──────────────────────  │                            │            │
│    │  PublicKeyCredential      │                            │            │
│    │  RequestOptions (JSON)    │                            │            │
│    │                           │                            │            │
│    │  navigator.credentials.get(options)                    │            │
│    │ ──────────────────────────────────────────────────────► │            │
│    │                                                        │  find      │
│    │                                                        │  key pair, │
│    │                                                        │  sign      │
│    │  ◄──────────────────────────────────────────────────── │  challenge │
│    │  assertion response                                    │            │
│    │  (credentialId, signedChallenge, userHandle)            │            │
│    │                           │                            │            │
│    │  POST /login/webauthn     │                            │            │
│    │  (assertion response)     │                            │            │
│    │ ────────────────────────► │                            │            │
│    │                           │  verify signature against  │            │
│    │                           │  stored public key,        │            │
│    │                           │  establish session          │            │
│    │  ◄──────────────────────  │                            │            │
│    │  authenticated session    │                            │            │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

The server never sees the private key. It only stores the public key during registration and verifies signatures against it during authentication. Spring Security handles all the cryptographic verification internally -- you provide the storage layer.

## Dependencies

Add the Spring Security WebAuthn module alongside the standard Spring Security starter:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-webauthn</artifactId>
</dependency>
```

This module ships with Spring Security 6.4+ / Spring Boot 3.4+. It provides built-in filters and endpoints for the WebAuthn protocol so you don't need a third-party library.

## The Two Protocols

Passkeys use the WebAuthn standard which has two ceremonies:

1. **Registration (attestation)** -- the user creates a new credential on their device
2. **Authentication (assertion)** -- the user proves they own a previously registered credential

Both follow the same pattern: server generates a challenge with options, the browser calls the WebAuthn API, and the browser sends the result back to the server for verification.

## What Spring Security Provides Out of the Box

When you configure `.webAuthn()` in your security filter chain, Spring Security automatically registers these endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/webauthn/register/options` | POST | Returns `PublicKeyCredentialCreationOptions` for registration |
| `/webauthn/register` | POST | Receives and validates the attestation response |
| `/webauthn/register/{credentialId}` | DELETE | Removes a registered credential |
| `/webauthn/authenticate/options` | POST | Returns `PublicKeyCredentialRequestOptions` for login |
| `/login/webauthn` | POST | Receives and validates the assertion response |

You do NOT need to write controllers for these. Spring Security handles the cryptographic verification, challenge management, and credential storage internally. What you DO need to provide are the repository implementations that tell Spring Security how to store and retrieve users and credentials from your database.

## Server-Side Implementation

### 1. Configure the Security Filter Chain

The key part is the `.webAuthn()` DSL block where you configure the relying party (RP) settings:

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/login", "/login/webauthn",
                    "/webauthn/**", "/js/**", "/css/**")
            .permitAll()
            .anyRequest().authenticated()
        )
        .formLogin(form -> form
            .loginPage("/login")
            .defaultSuccessUrl("/portal", true)
        )
        .webAuthn(webAuthn -> webAuthn
            .rpName("My Application")
            .rpId("localhost")
            .allowedOrigins("http://localhost:8080")
        );

    return http.build();
}
```

**Important:** The `/webauthn/**` and `/login/webauthn` paths must be `permitAll()` -- they are the Spring Security WebAuthn endpoints. If you forget these, the browser won't be able to reach the options/verification endpoints.

### 2. The User Entity

Your user entity needs a `userHandle` field -- a random 32-byte identifier that WebAuthn uses to map credentials to users. This is NOT the same as your database primary key or the email. It's an opaque, privacy-preserving identifier.

```java
@Entity
public class AppUser {
    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = true) // nullable if passkey-only users are allowed
    private String password;

    @Column(name = "user_handle", nullable = false)
    private byte[] userHandle;
}
```

Generate the `userHandle` with `SecureRandom` during registration:

```java
byte[] userHandle = new byte[32];
new SecureRandom().nextBytes(userHandle);
```

### 3. The Credential Entity

Each passkey credential gets its own row. A user can have multiple passkeys.

```java
@Entity
public class PasskeyCredential {
    @Id @GeneratedValue
    private Long id;

    @Column(name = "credential_id", nullable = false, length = 1024)
    private byte[] credentialId;

    @Column(name = "public_key", nullable = false, length = 2048)
    private byte[] publicKey;

    @Column(name = "signature_count", nullable = false)
    private long signatureCount;

    private String label;
    private Instant createdAt;
    private Instant lastUsed;
    private boolean uvInitialized;
    private boolean backupEligible;
    private boolean backupState;

    @Column(length = 4096)
    private byte[] attestationObject;

    @Column(length = 4096)
    private byte[] attestationClientDataJSON;

    private String transports; // comma-separated: "internal,hybrid"

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;
}
```

### 4. Implement `PublicKeyCredentialUserEntityRepository`

This interface tells Spring Security how to look up users by their WebAuthn `userHandle` or by username. Spring Security calls this during both registration and authentication.

```java
@Service
@RequiredArgsConstructor
public class JpaPublicKeyCredentialUserEntityRepository
        implements PublicKeyCredentialUserEntityRepository {

    private final AppUserRepository appUserRepository;

    @Override
    public PublicKeyCredentialUserEntity findById(Bytes id) {
        return appUserRepository.findByUserHandle(id.getBytes())
                .map(this::toUserEntity)
                .orElse(null);
    }

    @Override
    public PublicKeyCredentialUserEntity findByUsername(String username) {
        return appUserRepository.findByEmail(username)
                .map(this::toUserEntity)
                .orElse(null);
    }

    @Override
    public void save(PublicKeyCredentialUserEntity userEntity) {
        // No-op if you create the AppUser yourself during registration.
        // Spring Security calls this but the user already exists at this point.
    }

    @Override
    public void delete(Bytes id) {
        // Implement if you need to clean up users when all credentials are removed
    }

    private PublicKeyCredentialUserEntity toUserEntity(AppUser user) {
        return ImmutablePublicKeyCredentialUserEntity.builder()
                .name(user.getEmail())
                .id(new Bytes(user.getUserHandle()))
                .displayName(user.getEmail())
                .build();
    }
}
```

**Key point:** The `save()` method can be a no-op. Spring Security calls it during registration, but if you've already created the `AppUser` in your own registration flow (before the WebAuthn ceremony starts), the user already exists. You just need `findById` and `findByUsername` to work correctly.

### 5. Implement `UserCredentialRepository`

This is the more substantial interface. It tells Spring Security how to store, retrieve, and delete passkey credentials.

```java
@Service
@RequiredArgsConstructor
public class JpaUserCredentialRepository implements UserCredentialRepository {

    private final PasskeyCredentialRepository passkeyRepo;
    private final AppUserRepository appUserRepo;

    @Override
    @Transactional
    public void save(CredentialRecord record) {
        PasskeyCredential entity = passkeyRepo
                .findByCredentialId(record.getCredentialId().getBytes())
                .orElseGet(PasskeyCredential::new);

        AppUser user = appUserRepo
                .findByUserHandle(record.getUserEntityUserId().getBytes())
                .orElseThrow(() -> new IllegalStateException("User not found"));

        entity.setCredentialId(record.getCredentialId().getBytes());
        entity.setPublicKey(record.getPublicKey().getBytes());
        entity.setSignatureCount(record.getSignatureCount());
        entity.setLabel(record.getLabel() != null ? record.getLabel() : "Passkey");
        entity.setCreatedAt(record.getCreated() != null ? record.getCreated() : Instant.now());
        entity.setLastUsed(record.getLastUsed());
        entity.setUvInitialized(record.isUvInitialized());
        entity.setBackupEligible(record.isBackupEligible());
        entity.setBackupState(record.isBackupState());
        entity.setUser(user);

        if (record.getAttestationObject() != null)
            entity.setAttestationObject(record.getAttestationObject().getBytes());
        if (record.getAttestationClientDataJSON() != null)
            entity.setAttestationClientDataJSON(record.getAttestationClientDataJSON().getBytes());
        if (record.getTransports() != null) {
            String transportsStr = record.getTransports().stream()
                    .map(AuthenticatorTransport::getValue)
                    .collect(Collectors.joining(","));
            entity.setTransports(transportsStr);
        }

        passkeyRepo.save(entity);
    }

    @Override
    public CredentialRecord findByCredentialId(Bytes credentialId) {
        return passkeyRepo.findByCredentialId(credentialId.getBytes())
                .map(this::toCredentialRecord)
                .orElse(null);
    }

    @Override
    public List<CredentialRecord> findByUserId(Bytes userId) {
        return passkeyRepo.findAllByUser_UserHandle(userId.getBytes()).stream()
                .map(this::toCredentialRecord)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void delete(Bytes credentialId) {
        passkeyRepo.findByCredentialId(credentialId.getBytes())
                .ifPresent(passkeyRepo::delete);
    }

    private CredentialRecord toCredentialRecord(PasskeyCredential entity) {
        Set<AuthenticatorTransport> transports = new LinkedHashSet<>();
        if (entity.getTransports() != null && !entity.getTransports().isEmpty()) {
            for (String t : entity.getTransports().split(",")) {
                transports.add(AuthenticatorTransport.valueOf(t.trim()));
            }
        }

        return ImmutableCredentialRecord.builder()
                .credentialType(PublicKeyCredentialType.PUBLIC_KEY)
                .credentialId(new Bytes(entity.getCredentialId()))
                .publicKey(new ImmutablePublicKeyCose(entity.getPublicKey()))
                .signatureCount(entity.getSignatureCount())
                .uvInitialized(entity.isUvInitialized())
                .backupEligible(entity.isBackupEligible())
                .backupState(entity.isBackupState())
                .userEntityUserId(new Bytes(entity.getUser().getUserHandle()))
                .label(entity.getLabel())
                .lastUsed(entity.getLastUsed())
                .created(entity.getCreatedAt())
                .transports(transports)
                .attestationObject(entity.getAttestationObject() != null
                        ? new Bytes(entity.getAttestationObject()) : null)
                .attestationClientDataJSON(entity.getAttestationClientDataJSON() != null
                        ? new Bytes(entity.getAttestationClientDataJSON()) : null)
                .build();
    }
}
```

**Key points:**
- `save()` handles both new registrations and updates (e.g. signature count incremented after login). It looks up by `credentialId` first -- if found it updates, otherwise it creates.
- `findByCredentialId()` is called during authentication. Return `null` if not found (Spring Security will produce an authentication error).
- The conversion between your JPA entity and Spring Security's `CredentialRecord` / `ImmutableCredentialRecord` is the core glue work.

## Client-Side Implementation

### Base64URL Encoding

WebAuthn uses binary data (`ArrayBuffer`) but JSON can't carry binary, so everything is Base64URL-encoded. You need two utility functions:

```javascript
function base64UrlEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(base64url) {
    const padLength = (4 - (base64url.length % 4)) % 4;
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
        .padEnd(base64url.length + padLength, '=');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
```

### Registration Flow (Client)

```javascript
async function registerPasskey(label) {
    // 1. Get options from Spring Security
    const res = await fetch('/webauthn/register/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
    });
    const options = await res.json();

    // 2. Decode binary fields from Base64URL to ArrayBuffer
    options.challenge = base64UrlDecode(options.challenge);
    options.user.id = base64UrlDecode(options.user.id);
    if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(
            cred => ({ ...cred, id: base64UrlDecode(cred.id) })
        );
    }

    // 3. Call the browser WebAuthn API
    const credential = await navigator.credentials.create({ publicKey: options });

    // 4. Encode the response back to Base64URL and send to server
    const body = {
        publicKey: {
            credential: {
                id: credential.id,
                rawId: base64UrlEncode(credential.rawId),
                response: {
                    attestationObject: base64UrlEncode(credential.response.attestationObject),
                    clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
                    transports: credential.response.getTransports?.() ?? [],
                },
                type: credential.type,
                clientExtensionResults: credential.getClientExtensionResults(),
                authenticatorAttachment: credential.authenticatorAttachment ?? '',
            },
            label: label,
        },
    };

    await fetch('/webauthn/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
        body: JSON.stringify(body),
    });
}
```

**The user must be authenticated** when calling `/webauthn/register/options`. Spring Security needs to know which user is registering the credential. This means you either:
- Register passkeys from a portal page after the user has logged in, OR
- Create the user account and establish a session first, then immediately start the WebAuthn ceremony

### Authentication Flow (Client)

```javascript
async function loginWithPasskey() {
    // 1. Get options from Spring Security
    const res = await fetch('/webauthn/authenticate/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
    });
    const options = await res.json();

    // 2. Decode binary fields
    options.challenge = base64UrlDecode(options.challenge);
    if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(
            cred => ({ ...cred, id: base64UrlDecode(cred.id) })
        );
    }

    // 3. Call the browser WebAuthn API
    const assertion = await navigator.credentials.get({ publicKey: options });

    // 4. Encode and send to server
    const body = {
        id: assertion.id,
        rawId: base64UrlEncode(assertion.rawId),
        response: {
            authenticatorData: base64UrlEncode(assertion.response.authenticatorData),
            clientDataJSON: base64UrlEncode(assertion.response.clientDataJSON),
            signature: base64UrlEncode(assertion.response.signature),
            userHandle: assertion.response.userHandle
                ? base64UrlEncode(assertion.response.userHandle) : undefined,
        },
        credType: assertion.type,
        clientExtensionResults: assertion.getClientExtensionResults(),
        authenticatorAttachment: assertion.authenticatorAttachment,
    };

    const loginRes = await fetch('/login/webauthn', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
        body: JSON.stringify(body),
    });

    const result = await loginRes.json();
    window.location.href = result.redirectUrl || '/portal';
}
```

## Registration During Signup (Passkey-Only Users)

If you want users to sign up with a passkey (no password), there's a chicken-and-egg problem: Spring Security needs an authenticated session to register a credential, but the user doesn't exist yet.

The solution is a two-step flow:

1. **Create the user account and establish a session** via your own endpoint
2. **Run the WebAuthn ceremony** against the now-authenticated session
3. **Roll back if the ceremony fails** (user cancels the browser prompt)

```java
@PostMapping("/register/passkey/start")
@ResponseBody
public ResponseEntity<?> startPasskeyRegistration(@RequestBody Map<String, String> body,
                                                   HttpServletRequest request) {
    String email = body.get("email");

    // Create user without password
    userService.registerUserForPasskey(email);

    // Establish session so /webauthn/register/options knows who's registering
    var auth = new UsernamePasswordAuthenticationToken(
            email, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(auth);
    SecurityContextHolder.setContext(context);
    request.getSession(true).setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

    return ResponseEntity.ok(Map.of("success", true));
}

@PostMapping("/register/passkey/cancel")
@ResponseBody
public ResponseEntity<?> cancelPasskeyRegistration(HttpServletRequest request) {
    // User cancelled the WebAuthn prompt -- delete the half-created account
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth != null) {
        userService.deleteByEmail(auth.getName());
    }
    SecurityContextHolder.clearContext();
    return ResponseEntity.ok(Map.of("success", true));
}
```

On the client side, wrap the WebAuthn ceremony in a try/catch and call the cancel endpoint on failure:

```javascript
// Step 1: create account
await fetch('/register/passkey/start', { method: 'POST', body: JSON.stringify({ email }) });

try {
    // Step 2: WebAuthn ceremony
    await registerPasskey('My Passkey');
} catch (err) {
    // Step 3: roll back on failure
    await fetch('/register/passkey/cancel', { method: 'POST' });
    throw err;
}

window.location.href = '/portal';
```

## Custom Success/Failure Handlers

Spring Security's default WebAuthn filter returns basic responses. You'll likely want custom handlers for better UX. You need to grab the `WebAuthnAuthenticationFilter` from the built filter chain and set your handlers:

```java
SecurityFilterChain chain = http.build();

chain.getFilters().stream()
    .filter(f -> f instanceof WebAuthnAuthenticationFilter)
    .map(f -> (WebAuthnAuthenticationFilter) f)
    .findFirst()
    .ifPresent(filter -> {
        filter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.setContentType("application/json");
            // Return JSON with redirect URL so JS can navigate
            new JsonMapper().writeValue(response.getOutputStream(),
                Map.of("redirectUrl", "/portal", "authenticated", true));
        });
        filter.setAuthenticationFailureHandler((request, response, exception) -> {
            response.setStatus(401);
            response.setContentType("application/json");
            new JsonMapper().writeValue(response.getOutputStream(),
                Map.of("error", "Passkey authentication failed"));
        });
    });
```

This is necessary because the login happens via a `fetch()` call from JavaScript, not a form submit. The client needs a JSON response it can act on, not a redirect.

## Things to Keep an Eye On

### CSRF Protection

All POST endpoints need CSRF tokens. The simplest approach: put the token in `<meta>` tags and read them in JavaScript:

```html
<meta name="csrf-token" th:content="${_csrf.token}" />
<meta name="csrf-header" th:content="${_csrf.headerName}" />
```

```javascript
function csrfHeaders() {
    return {
        [document.querySelector('meta[name="csrf-header"]').content]:
            document.querySelector('meta[name="csrf-token"]').content,
        'Content-Type': 'application/json',
    };
}
```

### Relying Party ID and Origins

The RP ID (`rpId`) must match the domain the page is served from. For local development, use `localhost`. The allowed origins must include the full origin with protocol and port.

```properties
app.webauthn.rp-id=localhost
app.webauthn.allowed-origins=http://localhost:8080
```

In production, the RP ID must match your domain (e.g. `example.com`) and origins must use HTTPS. **WebAuthn does not work over plain HTTP** except on `localhost`. If the RP ID doesn't match the page origin, the browser will reject the WebAuthn ceremony silently.

### The Request/Response JSON Format

Spring Security expects a specific JSON structure for the registration and authentication endpoints. This is the part that's easy to get wrong. The registration body wraps everything under `publicKey.credential`, while the authentication body is flat. Look at the client-side code carefully -- mismatched field names will cause silent failures.

### Signature Count

The `signatureCount` is an anti-cloning mechanism. Each time an authenticator is used, it increments a counter. The server stores the last known count and rejects assertions where the count hasn't increased (which would indicate a cloned authenticator). Your `save()` method handles this automatically since Spring Security updates the `CredentialRecord` after each successful authentication.

### Database Loss = Locked-Out Users

If you lose your credential database, all registered passkeys become useless. The browser still has the private keys, but the server no longer has the matching public keys. Users will see auth failures. Log these clearly so you can diagnose the issue:

```java
if (credential == null) {
    log.warn("No credential found for credentialId={}. "
        + "Total credentials in DB: {}. "
        + "This usually means the passkey was registered against a previous database.",
        credentialId, totalCount);
}
```

### User Handle vs Username

The `userHandle` is WebAuthn's way of identifying a user without revealing their email/username to the authenticator. It's a 32-byte random value. Don't confuse it with your database ID. The mapping is: `userHandle` <-> `AppUser` <-> `email`. Both `findById(Bytes userHandle)` and `findByUsername(String email)` in your user entity repository must work correctly.

### Transports

When the browser creates a credential, it may report the transport types the authenticator supports (`internal`, `hybrid`, `usb`, `ble`, `nfc`). Store these -- they're included in `allowCredentials` during authentication so the browser knows which transport to try. Store them as a comma-separated string and parse them back into `AuthenticatorTransport` enum values.

### `NotAllowedError` on the Client

This is the most common error. It fires when the user cancels the browser's passkey dialog or when the operation times out. Always catch it and show a user-friendly "cancelled" message instead of a generic error.

### Permitted URL Paths

Make sure these paths are accessible without authentication in your security config:

- `/webauthn/register/options` -- needs auth (user must be logged in)
- `/webauthn/register` -- needs auth
- `/webauthn/authenticate/options` -- must be public (called from login page)
- `/login/webauthn` -- must be public (called from login page)

The pattern `/webauthn/**` covers the registration options and submission. `/login/webauthn` needs to be explicitly listed.

## Summary

The server-side work boils down to:

1. Add the `spring-security-webauthn` dependency
2. Configure `.webAuthn()` in your security filter chain with RP settings
3. Add a `userHandle` byte field to your user entity
4. Create a credential entity with all the WebAuthn fields
5. Implement `PublicKeyCredentialUserEntityRepository` (user lookup by handle/username)
6. Implement `UserCredentialRepository` (credential CRUD + conversion to/from `CredentialRecord`)

The client-side work boils down to:

1. Base64URL encode/decode utilities
2. Fetch options from the server, decode binary fields, call `navigator.credentials.create()` or `.get()`
3. Encode the response back to Base64URL and POST it to the server
4. Handle the JSON response (redirect on success, show error on failure)

Everything else -- challenge generation, cryptographic verification, public key parsing -- is handled by Spring Security internally.
