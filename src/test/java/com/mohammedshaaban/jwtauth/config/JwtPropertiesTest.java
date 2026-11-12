package com.mohammedshaaban.jwtauth.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import static org.junit.jupiter.api.Assertions.*;
import io.jsonwebtoken.JwtException;
import org.springframework.boot.test.context.SpringBootTest;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ConstraintViolation;
import java.util.Set;

class JwtPropertiesTest {

    private static Validator validator;

    private JwtProperties jwtProperties = new JwtProperties();

    @BeforeAll
    static void setUp() {
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    @Test
    @DisplayName("Test valid secret key for JwtProperties")
    void testValidJwtProperties() {
        String validSecret = "abcdefg6f1234567890123456789012g"; // 32 characters
        jwtProperties.setSecret(validSecret); // 32 characters
        assertTrue(validator.validate(jwtProperties).isEmpty());
    }

    @Test
    @DisplayName("Test invalid secret key for JwtProperties")
    void testInvalidJwtProperties() {
        String invalidSecret = "abcdefg6f1234567890123456789012"; // 31 characters
        jwtProperties.setSecret(invalidSecret);
        assertFalse(validator.validate(jwtProperties).isEmpty());
    }
}
