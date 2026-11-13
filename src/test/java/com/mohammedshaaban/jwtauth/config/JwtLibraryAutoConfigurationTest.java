package com.mohammedshaaban.jwtauth.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.mohammedshaaban.jwtauth.filters.JwtAuthenticationFilter;
import com.mohammedshaaban.jwtauth.services.JwtService;

class JwtLibraryAutoConfigurationTest {

    // represents a minimal web application context with the auto-configuration
    // under test
    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtLibraryAutoConfiguration.class))
            .withPropertyValues("jwt.secret=" + "a".repeat(32));

    @Test
    @DisplayName("Registers JwtService and filter when a UserDetailsService exists")
    void registersDefaultBeans() {
        runner.withBean(UserDetailsService.class, () -> mock(UserDetailsService.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(JwtService.class);
                    assertThat(context).hasSingleBean(JwtAuthenticationFilter.class);
                });
    }

}