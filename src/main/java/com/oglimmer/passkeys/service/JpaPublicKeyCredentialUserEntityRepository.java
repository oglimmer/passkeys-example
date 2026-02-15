package com.oglimmer.passkeys.service;

import com.oglimmer.passkeys.entity.AppUser;
import com.oglimmer.passkeys.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class JpaPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {

    private final AppUserRepository appUserRepository;

    @Override
    public PublicKeyCredentialUserEntity findById(Bytes id) {
        log.debug("Looking up user entity by userHandle={}", id);
        return appUserRepository.findByUserHandle(id.getBytes())
                .map(this::toUserEntity)
                .orElseGet(() -> {
                    log.warn("No user found for userHandle={}", id);
                    return null;
                });
    }

    @Override
    public PublicKeyCredentialUserEntity findByUsername(String username) {
        log.debug("Looking up user entity by username={}", username);
        return appUserRepository.findByEmail(username)
                .map(this::toUserEntity)
                .orElseGet(() -> {
                    log.debug("No user entity found for username={}", username);
                    return null;
                });
    }

    @Override
    public void save(PublicKeyCredentialUserEntity userEntity) {
        // The user entity is created during registration via RegistrationController,
        // so this is only called if Spring Security needs to persist a new mapping.
        // For our flow, the AppUser already exists with the userHandle set.
        log.debug("save() called for user={} (no-op, user already exists)", userEntity.getName());
    }

    @Override
    public void delete(Bytes id) {
        log.debug("delete() called for userHandle={} (no-op)", id);
    }

    private PublicKeyCredentialUserEntity toUserEntity(AppUser user) {
        return ImmutablePublicKeyCredentialUserEntity.builder()
                .name(user.getEmail())
                .id(new Bytes(user.getUserHandle()))
                .displayName(user.getEmail())
                .build();
    }
}
