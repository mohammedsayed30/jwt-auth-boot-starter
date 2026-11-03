package com.mohammedshaaban.jwtauth.services;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Collections;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import static org.mockito.Mockito.*;

import com.mohammedshaaban.jwtauth.config.JwtProperties;

class JwtServiceTest {

    // expiration time of 1 hour
    private static final Duration EXPIRATION = Duration.ofMinutes(30);

    // secret key for testing (Base64-encoded)
    private static final String SECRET = Base64.getEncoder().encodeToString(
            "0123456789012345678901234567890123456789".getBytes(StandardCharsets.UTF_8));

    private static final UserDetails USER_DETAILS = User
            .withUsername("testuser")
            .password("testpassword")
            .authorities(Collections.emptyList()) // no roles
            .build();

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        // Mock JwtProperties to return dummy test secret and expiration time
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret(SECRET);
        jwtProperties.setExpirationTime(EXPIRATION);

        // Create JwtService with mocked properties
        jwtService = new JwtService(jwtProperties);
    }

    @Test
    void generateToken_returnsCompactJwt() {
        String token = jwtService.generateToken(USER_DETAILS);

        assertNotNull(token);
        assertEquals(3, token.split("\\.").length); // header.payload.signature
    }
}
