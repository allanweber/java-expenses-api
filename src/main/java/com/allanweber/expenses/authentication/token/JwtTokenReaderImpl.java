package com.allanweber.expenses.authentication.token;

import com.allanweber.expenses.authentication.AccessTokenInfo;
import com.allanweber.expenses.authentication.ContextUser;
import com.allanweber.expenses.authentication.JwtTokenProvider;
import com.allanweber.expenses.authentication.JwtTokenReader;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class JwtTokenReaderImpl implements JwtTokenReader {

    private final Logger logger = LoggerFactory.getLogger(JwtTokenReaderImpl.class);

    private final SecretKey secretKey;

    private final JwtProperties properties;

    public JwtTokenReaderImpl(JwtProperties jwtProperties) {
        this.properties = jwtProperties;
        secretKey = Keys.hmacShaKeyFor(jwtProperties.privateKey().getBytes());
    }

    @Override
    public Authentication getAuthentication(String token) {
        Jws<Claims> jwsClaims = parseToken(token);
        Collection<? extends GrantedAuthority> authorities = getAuthorities(jwsClaims);
        ContextUser principal = new ContextUser(jwsClaims.getPayload().getSubject(), getTenancyId(jwsClaims), getTenancyName(jwsClaims));
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    @Override
    public AccessTokenInfo getAccessTokenInfo(String token) {
        Jws<Claims> jwsClaims = parseToken(token);
        List<String> authorities = getAuthorities(jwsClaims).stream().map(SimpleGrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        return new AccessTokenInfo(jwsClaims.getPayload().getSubject(), getTenancyId(jwsClaims), getTenancyName(jwsClaims), authorities);
    }

    @Override
    public boolean isTokenValid(String token) {
        boolean isValid = false;
        try {
            Jws<Claims> claims = parseToken(token);
            boolean sameIssuer = properties.issuer().equals(claims.getPayload().getIssuer());
            boolean sameAudience = claims.getPayload().getAudience().contains(properties.audience());
            isValid = sameIssuer && sameAudience;
        } catch (ExpiredJwtException e) {
            logger.error("Token expired: {}", e.getMessage());
        }
        return isValid;
    }

    private List<SimpleGrantedAuthority> getAuthorities(Jws<Claims> token) {
        return ((List<?>) token.getPayload().get(JwtTokenProvider.SCOPES))
                .stream()
                .map(authority -> new SimpleGrantedAuthority((String) authority))
                .collect(Collectors.toList());
    }

    private Long getTenancyId(Jws<Claims> token) {
        return Optional.ofNullable(token.getPayload().get(JwtTokenProvider.TENANCY_ID))
                .map(Object::toString)
                .map(Long::parseLong)
                .orElse(null);
    }

    private String getTenancyName(Jws<Claims> token) {
        return Optional.ofNullable(token.getPayload().get(JwtTokenProvider.TENANCY_NAME))
                .map(Object::toString)
                .orElse(null);
    }

    private Jws<Claims> parseToken(String token) {
        return Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token);
    }
}
