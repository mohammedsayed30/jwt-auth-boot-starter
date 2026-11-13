package io.github.mohammedshaaban.jwtauth.filters;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import io.github.mohammedshaaban.jwtauth.config.JwtProperties;
import io.github.mohammedshaaban.jwtauth.filters.JwtAuthenticationFilter;
import io.github.mohammedshaaban.jwtauth.services.JwtService;

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
import io.jsonwebtoken.JwtException;

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

    @Test
    void doFilterInternal_passInValidToken() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Bearer bad.token");
        when(jwtService.extractUsername("bad.token")).thenThrow(new JwtException("Invalid token"));

        // Call the method under test
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Verify that the filter chain was called
        verify(filterChain).doFilter(request, response);
        // Verify that the security context was not set
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterInternal_passNoHeader() throws Exception {
        when(request.getHeader("Authorization")).thenReturn(null);

        // Call the method under test
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Verify that the filter chain was called
        verify(filterChain).doFilter(request, response);
        // Verify that neither jwt service or user datails service were called
        verifyNoInteractions(jwtService, userDetailsService);
        // Verify that the security context was not set
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterInternal_passNonBearerHeader() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("InvalidHeader");

        // Call the method under test
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Verify that the filter chain was called
        verify(filterChain).doFilter(request, response);
        // Verify that neither jwt service or user datails service were called
        verifyNoInteractions(jwtService, userDetailsService);
        // Verify that the security context was not set
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

}
