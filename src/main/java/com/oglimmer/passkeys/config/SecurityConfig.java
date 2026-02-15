package com.oglimmer.passkeys.config;

import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;

import java.io.IOException;
import java.util.Map;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.webauthn.rp-id}")
    private String rpId;

    @Value("${app.webauthn.rp-name}")
    private String rpName;

    @Value("${app.webauthn.allowed-origins}")
    private String allowedOrigins;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/register", "/register/passkey/**",
                                "/login", "/login/webauthn",
                                "/css/**", "/js/**", "/webauthn/**")
                        .permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/portal", true)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .webAuthn(webAuthn -> webAuthn
                        .rpName(rpName)
                        .rpId(rpId)
                        .allowedOrigins(allowedOrigins)
                )
        ;

        SecurityFilterChain chain = http.build();

        // Add logging failure handler to the WebAuthn filter
        chain.getFilters().stream()
                .filter(f -> f instanceof WebAuthnAuthenticationFilter)
                .map(f -> (WebAuthnAuthenticationFilter) f)
                .findFirst()
                .ifPresent(filter -> {
                    filter.setAuthenticationFailureHandler(new LoggingWebAuthnFailureHandler());
                    filter.setAuthenticationSuccessHandler(new WebAuthnSuccessHandler("/portal"));
                });

        return chain;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private static class WebAuthnSuccessHandler implements AuthenticationSuccessHandler {
        private final JsonMapper jsonMapper = JsonMapper.builder().build();
        private final RequestCache requestCache = new HttpSessionRequestCache();
        private final String defaultRedirectUrl;

        WebAuthnSuccessHandler(String defaultRedirectUrl) {
            this.defaultRedirectUrl = defaultRedirectUrl;
        }

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authentication) throws IOException {
            SavedRequest savedRequest = requestCache.getRequest(request, response);
            String redirectUrl = (savedRequest != null) ? savedRequest.getRedirectUrl() : defaultRedirectUrl;
            requestCache.removeRequest(request, response);

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            jsonMapper.writeValue(response.getOutputStream(),
                    Map.of("redirectUrl", redirectUrl, "authenticated", true));
        }
    }

    private static class LoggingWebAuthnFailureHandler implements AuthenticationFailureHandler {
        private final JsonMapper jsonMapper = JsonMapper.builder().build();

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException exception) throws IOException {
            String message = exception.getMessage();
            Throwable cause = exception.getCause();
            String causeMessage = cause != null ? cause.getMessage() : null;

            log.error("WebAuthn authentication failed: {} | cause: {}", message, causeMessage, exception);

            String userMessage = toUserMessage(message, cause);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            jsonMapper.writeValue(response.getOutputStream(), Map.of("error", userMessage));
        }

        private String toUserMessage(String message, Throwable cause) {
            if (message == null) return "Authentication failed";

            if (message.contains("credentialRecord") && message.contains("null")) {
                return "This passkey is no longer registered. Please remove it from your browser/device and register a new one.";
            }
            if (message.contains("No PublicKeyCredentialRequestOptions found")) {
                return "Session expired. Please refresh the page and try again.";
            }
            if (message.contains("Unable to authenticate the PublicKeyCredential")) {
                return "Invalid passkey response. Please try again.";
            }
            return "Passkey authentication failed. Please try again or sign in with your password.";
        }
    }
}
