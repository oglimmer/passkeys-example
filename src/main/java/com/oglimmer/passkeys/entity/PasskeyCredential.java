package com.oglimmer.passkeys.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Base64;

@Entity
@Table(name = "passkey_credential")
@Getter
@Setter
@NoArgsConstructor
public class PasskeyCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "credential_id", nullable = false, length = 1024)
    private byte[] credentialId;

    @Column(name = "public_key", nullable = false, length = 2048)
    private byte[] publicKey;

    @Column(name = "signature_count", nullable = false)
    private long signatureCount;

    @Column(nullable = false)
    private String label;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_used")
    private Instant lastUsed;

    @Column(name = "uv_initialized", nullable = false)
    private boolean uvInitialized;

    @Column(name = "backup_eligible", nullable = false)
    private boolean backupEligible;

    @Column(name = "backup_state", nullable = false)
    private boolean backupState;

    @Column(name = "attestation_object", length = 4096)
    private byte[] attestationObject;

    @Column(name = "attestation_client_data_json", length = 4096)
    private byte[] attestationClientDataJSON;

    @Column(name = "transports")
    private String transports;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    public String getCredentialIdBase64() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);
    }
}
