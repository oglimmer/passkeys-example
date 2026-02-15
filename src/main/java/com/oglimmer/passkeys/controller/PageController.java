package com.oglimmer.passkeys.controller;

import com.oglimmer.passkeys.entity.AppUser;
import com.oglimmer.passkeys.entity.PasskeyCredential;
import com.oglimmer.passkeys.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class PageController {

    private final UserService userService;

    @GetMapping("/")
    public String landing() {
        return "landing";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/portal")
    public String portal(Authentication authentication, Model model) {
        String email = authentication.getName();
        model.addAttribute("email", email);

        AppUser user = userService.findByEmail(email).orElse(null);
        if (user != null) {
            List<PasskeyCredential> passkeys = userService.getPasskeysForUser(user);
            model.addAttribute("passkeys", passkeys);
        }

        return "portal";
    }
}
