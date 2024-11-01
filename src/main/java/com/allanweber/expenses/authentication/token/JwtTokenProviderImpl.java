package com.allanweber.expenses.authentication.token;

import com.allanweber.expenses.authentication.ContextUser;
import com.allanweber.expenses.authentication.JwtTokenProvider;
import com.allanweber.expenses.utils.DateHelper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProviderImpl implements JwtTokenProvider {

    private final JwtProperties properties;

    private final SecretKey secretKey;

    public JwtTokenProviderImpl(JwtProperties jwtProperties) {
        this.properties = jwtProperties;
        secretKey = Keys.hmacShaKeyFor(jwtProperties.privateKey().getBytes());
    }

    @Override
    public TokenData generateAccessToken(ContextUser user, List<String> authorities) {
        if (null == authorities || authorities.isEmpty()) {
            throw new JwtException(HttpStatus.UNAUTHORIZED, "User has no authorities");
        }

        Date issuedAt = DateHelper.getUTCDatetimeAsDate();
        String accessToken = Jwts.builder()
                .signWith(this.secretKey)
                .header().add(HEADER_TYP, TOKEN_TYPE).and()
                .issuer(properties.issuer())
                .audience().add(properties.audience()).and()
                .subject(user.email())
                .issuedAt(issuedAt)
                .expiration(getExpirationDate(properties.accessTokenExpiration()))
                .claim(SCOPES, authorities)
                .claim(TENANCY_ID, user.tenancyId())
                .claim(TENANCY_NAME, user.tenancyName())
                .compact();

        return new TokenData(accessToken,
                issuedAt.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
    }

    @Override
    public TokenData generateRefreshToken(ContextUser user) {
        Date issuedAt = DateHelper.getUTCDatetimeAsDate();
        String refreshToken = Jwts.builder()
                .signWith(this.secretKey)
                .header().add(HEADER_TYP, TOKEN_TYPE).and()
                .issuer(properties.issuer())
                .audience().add(properties.audience()).and()
                .subject(user.email())
                .issuedAt(issuedAt)
                .expiration(getExpirationDate(properties.refreshTokenExpiration()))
                .claim(SCOPES, Collections.singletonList(REFRESH_TOKEN))
                .compact();

        return new TokenData(refreshToken,
                issuedAt.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
    }

    private Date getExpirationDate(Long expireIn) {
        return Date.from(LocalDateTime.now().plusSeconds(expireIn)
                .atZone(ZoneId.systemDefault())
                .toInstant());
    }
}
