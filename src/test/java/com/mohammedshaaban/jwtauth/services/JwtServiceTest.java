package com.mohammedshaaban.jwtauth.services;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Collections;

import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import static org.mockito.Mockito.*;
import java.util.Date;

import com.mohammedshaaban.jwtauth.config.JwtProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

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
    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        // Mock JwtProperties to return dummy test secret and expiration time
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret(SECRET);
        jwtProperties.setExpirationTime(EXPIRATION);

        // Create JwtService with mocked properties
        jwtService = new JwtService(jwtProperties);
        signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET));
    }

    private Claims parse(String token) {

        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7); // Remove "Bearer " prefix
        }
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Verifies that a generated token uses the compact JWT format.
     */
    @Test
    void generateToken_returnsCompactJwt() {
        String token = jwtService.generateToken(USER_DETAILS);

        assertNotNull(token);
        assertEquals(3, token.split("\\.").length); // header.payload.signature
    }

    /**
     * Verifies that the username is extracted from a valid token's subject.
     */
    @Test
    void extractUsername_fromValidToken() {
        String token = jwtService.generateToken(USER_DETAILS);
        String username = jwtService.extractUsername(token);

        assertEquals("testuser", username);
    }

    /**
     * Verifies that malformed token input is rejected by the JWT parser.
     */
    @Test
    void extractUsername_fromNonValidToken() {
        String invalidToken = "Bearer dummy.invalid.token";
        assertThrows(JwtException.class, () -> jwtService.extractUsername(invalidToken));
    }

    /**
     * Verifies that a generated token has an expiration matching the configured
     * lifetime.
     */
    @Test
    void extractExpiration_fromValidToken() {
        String token = jwtService.generateToken(USER_DETAILS);
        Date expiration = jwtService.extractExpiration(token);
        assertNotNull(expiration);

        // Calculate expected expiration (approx. 30 minutes from now)
        long currentTime = System.currentTimeMillis();
        long expirationTime = expiration.getTime();
        long expectedDurationMillis = Duration.ofMinutes(30).toMillis();

        // Verify that the expiration is roughly 30 minutes away (allowing a 2-second
        // test execution buffer)
        long difference = Math.abs((expirationTime - currentTime) - expectedDurationMillis);
        assertTrue(difference < 2000, "Token expiration should be approximately 30 minutes from creation");

    }

    /**
     * Verifies that a token with an immediate expiration is reported as expired.
     */
    @Test
    void isTokenExpired_returnsTrueForExpiredToken() {
        // Create a token that expires immediately
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret(SECRET);
        jwtProperties.setExpirationTime(Duration.ZERO); // immediate expiration

        JwtService immediateExpiryService = new JwtService(jwtProperties);
        String token = immediateExpiryService.generateToken(USER_DETAILS);

        assertNotNull(token);
        assertTrue(immediateExpiryService.isTokenExpired(token));
    }

    /**
     * Verifies that a token within its configured lifetime is not expired.
     */
    @Test
    void isTokenExpired_returnsFalseForValidToken() {

        String token = jwtService.generateToken(USER_DETAILS);

        assertNotNull(token);
        assertFalse(jwtService.isTokenExpired(token));
    }

    /**
     * Verifies that a signed, unexpired token for the user is valid.
     */
    @Test
    void isTokenValid_returnsTrueForValidToken() {

        String token = jwtService.generateToken(USER_DETAILS);

        assertNotNull(token);
        assertTrue(jwtService.isTokenValid(token, USER_DETAILS));
    }

    /**
     * Verifies that a token with an altered signature is not valid.
     */
    @Test
    void isTokenValid_returnsFalseForNonValidToken() {

        String token = jwtService.generateToken(USER_DETAILS);

        assertNotNull(token);
        // change the token to make it invalid
        String invalidToken = token + "invalid";

        assertFalse(jwtService.isTokenValid(invalidToken, USER_DETAILS));
    }

}
