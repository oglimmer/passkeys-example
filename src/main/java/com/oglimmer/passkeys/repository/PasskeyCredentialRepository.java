package com.oglimmer.passkeys.repository;

import com.oglimmer.passkeys.entity.AppUser;
import com.oglimmer.passkeys.entity.PasskeyCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, Long> {

    Optional<PasskeyCredential> findByCredentialId(byte[] credentialId);

    List<PasskeyCredential> findAllByUser(AppUser user);

    List<PasskeyCredential> findAllByUser_UserHandle(byte[] userHandle);
}
