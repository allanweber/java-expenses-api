package com.allanweber.expenses.authentication.token;

import com.allanweber.expenses.authentication.ContextUser;
import com.allanweber.expenses.authentication.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(SpringExtension.class)
class JwtTokenProviderImplTest {

    JwtTokenProvider tokenProvider;

    @BeforeEach
    public void setUp() {
        JwtProperties properties = new JwtProperties("zH4Hi0IjMZkjJvK990vKwpuUUGWhIrnGqxZxFiZKQ5pKV39yktm3VN3MkyPFN7Sn9WHHmgwr5ApMZstcFAdSYA==", 3600L,
                86400L, "issuer", "audience");
        tokenProvider = new JwtTokenProviderImpl(properties);
    }

    @Test
    @DisplayName("Given user and its roles when generateAccessToken, return JWT token")
    void generateAccessToken() {
        ContextUser user = new ContextUser("mail@mail.com", 1L, "tenancy");
        List<String> roles = singletonList("ROLE_USER");

        TokenData tokenData = tokenProvider.generateAccessToken(user, roles);

        assertThat(tokenData.token()).isNotEmpty();
        assertThat(tokenData.issuedAt()).isBefore(LocalDateTime.now());
    }

    @Test
    @DisplayName("Given user and its roles when generateRefreshToken, return JWT token")
    void generateRefreshToken() {
        ContextUser user = new ContextUser("mail@mail.com", 1L, "tenancy");
        List<String> roles = singletonList("ROLE_USER");

        TokenData tokenData = tokenProvider.generateRefreshToken(user);

        assertThat(tokenData.token()).isNotEmpty();
        assertThat(tokenData.issuedAt()).isBefore(LocalDateTime.now());
    }

    @Test
    @DisplayName("Given user with null roles when generateAccessToken, return exception")
    void nullRoles() {
        ContextUser user = new ContextUser("mail@mail.com", 1L, "tenancy");

        JwtException exception = assertThrows(
                JwtException.class,
                () -> tokenProvider.generateAccessToken(user, null),
                "User has no authorities");

        assertThat(exception.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("Given user with empty roles when generateAccessToken, return exception")
    void emptyRoles() throws IOException, NoSuchAlgorithmException {
        ContextUser user = new ContextUser("mail@mail.com", 1L, "tenancy");
        List<String> roles = emptyList();

        JwtException exception = assertThrows(
                JwtException.class,
                () -> tokenProvider.generateAccessToken(user, roles),
                "User has no authorities");

        assertThat(exception.getStatusCode().value()).isEqualTo(401);
    }
}