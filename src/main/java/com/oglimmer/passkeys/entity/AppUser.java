package com.oglimmer.passkeys.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "app_user")
@Getter
@Setter
@NoArgsConstructor
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = true)
    private String password;

    @Column(name = "user_handle", nullable = false)
    private byte[] userHandle;

    public AppUser(String email, String password, byte[] userHandle) {
        this.email = email;
        this.password = password;
        this.userHandle = userHandle;
    }
}
