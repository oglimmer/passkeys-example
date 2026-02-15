package com.oglimmer.passkeys.service;

import com.oglimmer.passkeys.entity.AppUser;
import com.oglimmer.passkeys.entity.PasskeyCredential;
import com.oglimmer.passkeys.repository.AppUserRepository;
import com.oglimmer.passkeys.repository.PasskeyCredentialRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.webauthn.api.*;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class JpaUserCredentialRepository implements UserCredentialRepository {

    private final PasskeyCredentialRepository passkeyRepo;
    private final AppUserRepository appUserRepo;

    @Override
    @Transactional
    public void delete(Bytes credentialId) {
        log.info("Deleting passkey credential [credentialId={}]", credentialId);
        passkeyRepo.findByCredentialId(credentialId.getBytes())
                .ifPresentOrElse(
                        cred -> {
                            passkeyRepo.delete(cred);
                            log.info("Deleted passkey credential [label={}, user={}]",
                                    cred.getLabel(), cred.getUser().getEmail());
                        },
                        () -> log.warn("Delete requested but no credential found [credentialId={}]", credentialId)
                );
    }

    @Override
    @Transactional
    public void save(CredentialRecord record) {
        PasskeyCredential entity = passkeyRepo.findByCredentialId(record.getCredentialId().getBytes())
                .orElseGet(PasskeyCredential::new);

        boolean isNew = entity.getId() == null;

        AppUser user = appUserRepo.findByUserHandle(record.getUserEntityUserId().getBytes())
                .orElseThrow(() -> {
                    log.error("Cannot save passkey: no user found for userHandle={}", record.getUserEntityUserId());
                    return new IllegalStateException(
                            "User not found for userHandle " + record.getUserEntityUserId());
                });

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

        if (record.getAttestationObject() != null) {
            entity.setAttestationObject(record.getAttestationObject().getBytes());
        }
        if (record.getAttestationClientDataJSON() != null) {
            entity.setAttestationClientDataJSON(record.getAttestationClientDataJSON().getBytes());
        }
        if (record.getTransports() != null) {
            String transportsStr = record.getTransports().stream()
                    .map(AuthenticatorTransport::getValue)
                    .collect(Collectors.joining(","));
            entity.setTransports(transportsStr);
        }

        passkeyRepo.save(entity);
        log.info("{} passkey credential [credentialId={}, label={}, user={}]",
                isNew ? "Registered new" : "Updated",
                record.getCredentialId(), entity.getLabel(), user.getEmail());
    }

    @Override
    public CredentialRecord findByCredentialId(Bytes credentialId) {
        log.debug("Looking up passkey credential [credentialId={}]", credentialId);
        Optional<PasskeyCredential> result = passkeyRepo.findByCredentialId(credentialId.getBytes());
        if (result.isEmpty()) {
            long totalCount = passkeyRepo.count();
            log.warn("Passkey authentication failed: no credential found for credentialId={}. "
                            + "There are {} passkey(s) in the database. "
                            + "This usually means the passkey was registered against a previous "
                            + "(now lost) database, or the credential was deleted.",
                    credentialId, totalCount);
            return null;
        }
        PasskeyCredential cred = result.get();
        log.debug("Found passkey credential [credentialId={}, label={}, user={}]",
                credentialId, cred.getLabel(), cred.getUser().getEmail());
        return toCredentialRecord(cred);
    }

    @Override
    public List<CredentialRecord> findByUserId(Bytes userId) {
        List<PasskeyCredential> creds = passkeyRepo.findAllByUser_UserHandle(userId.getBytes());
        log.debug("Found {} passkey credential(s) for userId={}", creds.size(), userId);
        return creds.stream()
                .map(this::toCredentialRecord)
                .collect(Collectors.toList());
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
                .attestationObject(entity.getAttestationObject() != null ? new Bytes(entity.getAttestationObject()) : null)
                .attestationClientDataJSON(entity.getAttestationClientDataJSON() != null ? new Bytes(entity.getAttestationClientDataJSON()) : null)
                .build();
    }
}
