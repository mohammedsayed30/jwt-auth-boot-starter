package com.mohammedshaaban.jwtauth.services;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

class JwtServiceTest {

    private static final UserDetails USER_DETAILS = User
            .withUsername("testuser")
            .password("testpassword")
            .authorities(Collections.emptyList()) // no roles
            .build();

    @Test
    void testGenerateToken() {
    }
}
