package com.allanweber.expenses.authentication.token;

import com.allanweber.expenses.authentication.AccessTokenInfo;
import com.allanweber.expenses.authentication.ContextUser;
import com.allanweber.expenses.authentication.JwtTokenReader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import static com.allanweber.expenses.authentication.JwtTokenProvider.*;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
class JwtTokenReaderImplTest {

    private static final String PRIVATE_KEY = "zH4Hi0IjMZkjJvK990vKwpuUUGWhIrnGqxZxFiZKQ5pKV39yktm3VN3MkyPFN7Sn9WHHmgwr5ApMZstcFAdSYA==";

    JwtTokenReader jwtTokenReader;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties(PRIVATE_KEY, 3600L,
                86400L, "TOKEN_ISSUER", "TOKEN_AUDIENCE");

        jwtTokenReader = new JwtTokenReaderImpl(properties);
    }

    @Test
    @DisplayName("Given access token return Authentication with tenancy")
    void authentication() {
        Date expiration = Date.from(LocalDateTime.now().plusSeconds(360).atZone(ZoneId.systemDefault()).toInstant());
        String token = mockAccessToken(expiration, singletonList("ROLE_USER"), 1L, "tenancy_1");

        Authentication authentication = jwtTokenReader.getAuthentication(token);
        assertThat(authentication).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(authentication.getCredentials()).isEqualTo(token);
        assertThat(((ContextUser) authentication.getPrincipal()).email()).isEqualTo("mail@mail.com");
        assertThat(((ContextUser) authentication.getPrincipal()).tenancyName()).isEqualTo("tenancy_1");
        assertThat(((ContextUser) authentication.getPrincipal()).tenancyId()).isEqualTo(1L);
        assertThat(((UsernamePasswordAuthenticationToken) authentication).getAuthorities()).hasSize(1);
        assertThat(authentication.getPrincipal())
                .isInstanceOf(ContextUser.class);
    }

    @Test
    @DisplayName("Given access token without tenancy return Authentication without tenancy")
    void authenticationException() {
        Date expiration = Date.from(LocalDateTime.now().plusSeconds(360).atZone(ZoneId.systemDefault()).toInstant());
        String token = mockAccessToken(expiration, singletonList("ROLE_USER"), null, null);

        Authentication authentication = jwtTokenReader.getAuthentication(token);
        assertThat(authentication).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(authentication.getCredentials()).isEqualTo(token);
        assertThat(((ContextUser) authentication.getPrincipal()).email()).isEqualTo("mail@mail.com");
        assertThat(((ContextUser) authentication.getPrincipal()).tenancyName()).isNull();
        assertThat(((ContextUser) authentication.getPrincipal()).tenancyId()).isNull();
        assertThat(((UsernamePasswordAuthenticationToken) authentication).getAuthorities()).hasSize(1);
        assertThat(authentication.getPrincipal())
                .isInstanceOf(ContextUser.class);
    }

    @Test
    @DisplayName("Given access token when getting Token Info return info")
    void accessTokenInfo() {
        Date expiration = Date.from(LocalDateTime.now().plusSeconds(360).atZone(ZoneId.systemDefault()).toInstant());
        String token = mockAccessToken(expiration, singletonList("ROLE_USER"), 1L, "tenancy_1");

        AccessTokenInfo accessTokenInfo = jwtTokenReader.getAccessTokenInfo(token);
        assertThat(accessTokenInfo.subject()).isEqualTo("mail@mail.com");
        assertThat(accessTokenInfo.tenancyName()).isEqualTo("tenancy_1");
        assertThat(accessTokenInfo.tenancyId()).isEqualTo(1L);
        assertThat(accessTokenInfo.scopes()).containsExactly("ROLE_USER");
    }


    @Test
    @DisplayName("Given access token without tenancy when getting Token Info without tenancy")
    void accessTokenInfoException() {
        Date expiration = Date.from(LocalDateTime.now().plusSeconds(360).atZone(ZoneId.systemDefault()).toInstant());
        String token = mockAccessToken(expiration, singletonList("ROLE_USER"), null, null);

        AccessTokenInfo accessTokenInfo = jwtTokenReader.getAccessTokenInfo(token);
        assertThat(accessTokenInfo.subject()).isEqualTo("mail@mail.com");
        assertThat(accessTokenInfo.tenancyName()).isNull();
        assertThat(accessTokenInfo.tenancyId()).isNull();
        assertThat(accessTokenInfo.scopes()).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("Given access token return it is valid")
    void validToken() {
        Date expiration = Date.from(LocalDateTime.now().plusSeconds(360).atZone(ZoneId.systemDefault()).toInstant());
        String token = mockAccessToken(expiration, singletonList("ROLE_USER"), null, null);

        boolean tokenValid = jwtTokenReader.isTokenValid(token);
        assertThat(tokenValid).isTrue();
    }

    @Test
    @DisplayName("Given access token return it is invalid because it has different issuer")
    void invalidTokenIssuer() {
        Date expiration = Date.from(LocalDateTime.now().plusSeconds(360).atZone(ZoneId.systemDefault()).toInstant());
        String token = mockAccessToken(expiration, singletonList("ROLE_USER"), null, null, "anotherissuer", "TOKEN_AUDIENCE");

        boolean tokenValid = jwtTokenReader.isTokenValid(token);
        assertThat(tokenValid).isFalse();
    }

    @Test
    @DisplayName("Given access token return it is invalid because it has different audience")
    void invalidTokenAudience() {
        Date expiration = Date.from(LocalDateTime.now().plusSeconds(360).atZone(ZoneId.systemDefault()).toInstant());
        String token = mockAccessToken(expiration, singletonList("ROLE_USER"), null, null, "anotherissuer", "anotherAudience");

        boolean tokenValid = jwtTokenReader.isTokenValid(token);
        assertThat(tokenValid).isFalse();
    }

    @Test
    @DisplayName("Given an expired token return it is invalid")
    void invalidTokenExpired() {
        Date expiration = Date.from(LocalDateTime.now().minusSeconds(360).atZone(ZoneId.systemDefault()).toInstant());
        String token = mockAccessToken(expiration, singletonList("ROLE_USER"), null, null);

        boolean tokenValid = jwtTokenReader.isTokenValid(token);
        assertThat(tokenValid).isFalse();
    }

    @Test
    @DisplayName("Given refresh token when getting Token Info return info")
    void refreshTokenInfo() {
        String token = mockRefreshToken();

        AccessTokenInfo accessTokenInfo = jwtTokenReader.getAccessTokenInfo(token);
        assertThat(accessTokenInfo.subject()).isEqualTo("mail@mail.com");
        assertThat(accessTokenInfo.tenancyName()).isNull();
        assertThat(accessTokenInfo.scopes()).containsExactly("REFRESH_TOKEN");
    }

    private String mockAccessToken(Date issuedAt, List<String> authorities, Long tenancyId, String tenancyName) {
        return mockAccessToken(issuedAt, authorities, tenancyId, tenancyName, "TOKEN_ISSUER", "TOKEN_AUDIENCE");
    }

    private String mockAccessToken(Date expiration, List<String> authorities, Long tenancyId, String tenancyName, String issuer, String audience) {
        SecretKey secretKey = Keys.hmacShaKeyFor(PRIVATE_KEY.getBytes());
        JwtBuilder jwtBuilder = Jwts.builder()
                .signWith(secretKey)
                .header().add(HEADER_TYP, TOKEN_TYPE).and()
                .issuer(issuer)
                .audience().add(audience).and()
                .subject("mail@mail.com")
                .issuedAt(Date.from(LocalDateTime.now()
                        .atZone(ZoneId.systemDefault())
                        .toInstant()))
                .expiration(expiration);

        if (authorities != null) {
            jwtBuilder.claim(SCOPES, authorities);
        }

        if (tenancyId != null) {
            jwtBuilder.claim(TENANCY_ID, tenancyId);
        }

        if (tenancyName != null) {
            jwtBuilder.claim(TENANCY_NAME, tenancyName);
        }

        return jwtBuilder.compact();
    }

    private String mockRefreshToken() {
        SecretKey secretKey = Keys.hmacShaKeyFor(PRIVATE_KEY.getBytes());
        return Jwts.builder()
                .signWith(secretKey)
                .header().add(HEADER_TYP, TOKEN_TYPE).and()
                .issuer("TOKEN_ISSUER")
                .audience().add("TOKEN_AUDIENCE").and()
                .subject("mail@mail.com")
                .issuedAt(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()))
                .expiration(Date.from(LocalDateTime.now().plusSeconds(360)
                        .atZone(ZoneId.systemDefault())
                        .toInstant()))
                .claim(SCOPES, singletonList("REFRESH_TOKEN"))
                .compact();
    }
}