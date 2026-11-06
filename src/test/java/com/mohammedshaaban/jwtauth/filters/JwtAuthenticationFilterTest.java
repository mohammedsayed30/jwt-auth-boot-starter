package com.mohammedshaaban.jwtauth.filters;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.mohammedshaaban.jwtauth.config.JwtProperties;
import com.mohammedshaaban.jwtauth.services.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.mockito.Mockito.*;
import java.util.Collections;
import org.springframework.security.core.context.SecurityContextHolder;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {
    private static final UserDetails USER_DETAILS = User
            .withUsername("testuser")
            .password("testpassword")
            .authorities(Collections.emptyList()) // no roles
            .build();

    @Mock
    private JwtService jwtService;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext(); // static state, must be reset between tests
    }

    @Test
    void doFilterInternal_passValidToken() throws Exception {
        // consider everything is work correctly that done beside the filter(the
        // required one)
        when(request.getHeader("Authorization")).thenReturn("Bearer validToken");
        when(jwtService.extractUsername("validToken")).thenReturn(USER_DETAILS.getUsername());
        when(userDetailsService.loadUserByUsername(USER_DETAILS.getUsername())).thenReturn(USER_DETAILS);
        when(jwtService.isTokenValid("validToken", USER_DETAILS)).thenReturn(true);

        // Call the method under test
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Verify that the filter chain was called
        verify(filterChain).doFilter(request, response);
        // Verify that the security context was set with the authenticated user
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

}
