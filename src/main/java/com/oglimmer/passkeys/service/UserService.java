package com.oglimmer.passkeys.service;

import com.oglimmer.passkeys.entity.AppUser;
import com.oglimmer.passkeys.entity.PasskeyCredential;
import com.oglimmer.passkeys.repository.AppUserRepository;
import com.oglimmer.passkeys.repository.PasskeyCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final AppUserRepository appUserRepository;
    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final PasswordEncoder passwordEncoder;

    public Optional<AppUser> findByEmail(String email) {
        return appUserRepository.findByEmail(email);
    }

    public boolean emailExists(String email) {
        return appUserRepository.findByEmail(email).isPresent();
    }

    public void registerUser(String email, String password) {
        byte[] userHandle = new byte[32];
        new SecureRandom().nextBytes(userHandle);
        AppUser user = new AppUser(email, passwordEncoder.encode(password), userHandle);
        appUserRepository.save(user);
    }

    public void registerUserForPasskey(String email) {
        byte[] userHandle = new byte[32];
        new SecureRandom().nextBytes(userHandle);
        AppUser user = new AppUser(email, null, userHandle);
        appUserRepository.save(user);
    }

    public void deleteByEmail(String email) {
        appUserRepository.findByEmail(email).ifPresent(appUserRepository::delete);
    }

    public List<PasskeyCredential> getPasskeysForUser(AppUser user) {
        return passkeyCredentialRepository.findAllByUser(user);
    }
}
