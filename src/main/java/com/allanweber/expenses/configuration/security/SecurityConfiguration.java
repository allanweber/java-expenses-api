package com.allanweber.expenses.configuration.security;

import com.allanweber.expenses.authentication.AuthorityType;
import com.allanweber.expenses.authentication.JwtTokenAuthenticationCheck;
import com.allanweber.expenses.authentication.UserPasswordAuthenticationManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;
import java.util.stream.Stream;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration {
    private final ServerAuthenticationExceptionEntryPoint serverAuthenticationExceptionEntryPoint;
    private final UserPasswordAuthenticationManager userPasswordAuthenticationManager;
    private final JwtTokenAuthenticationCheck jwtTokenAuthenticationCheck;

    public SecurityConfiguration(ServerAuthenticationExceptionEntryPoint serverAuthenticationExceptionEntryPoint, UserPasswordAuthenticationManager userPasswordAuthenticationManager, JwtTokenAuthenticationCheck jwtTokenAuthenticationCheck) {
        this.serverAuthenticationExceptionEntryPoint = serverAuthenticationExceptionEntryPoint;
        this.userPasswordAuthenticationManager = userPasswordAuthenticationManager;
        this.jwtTokenAuthenticationCheck = jwtTokenAuthenticationCheck;
    }

    @Bean
    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .exceptionHandling(custom -> custom.authenticationEntryPoint(serverAuthenticationExceptionEntryPoint))
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                .requestMatchers(getPublicPath()).permitAll()
                                .requestMatchers(getAdminPath()).hasAnyAuthority(AuthorityType.ADMINISTRATOR.name())
                                .requestMatchers(getTenancyAdminPath()).hasAnyAuthority(AuthorityType.TENANCY_ADMIN.name())
                                .anyRequest().hasAnyAuthority(AuthorityType.COMMON_USER.name())
                )
                .addFilterBefore(new JwtTokenAuthenticationFilter(jwtTokenAuthenticationCheck), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationManager(userPasswordAuthenticationManager)
                .cors(cors -> cors.configurationSource(getCorsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        return httpSecurity.build();
    }

    private static CorsConfigurationSource getCorsConfigurationSource() {
        return request -> {
            CorsConfiguration corsConfiguration = new CorsConfiguration()
                    .setAllowedOriginPatterns(List.of("*"))
                    .applyPermitDefaultValues();
            corsConfiguration.setAllowedMethods(Stream.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH").toList());
            return corsConfiguration;
        };
    }

    private String[] getPublicPath() {
        String[] monitoring = {"/health/**", "/prometheus", "/metrics*/**"};
        String[] authentication = {"/auth/**"};
        String[] swagger = {"/swagger-ui/**", "/v3/api-docs/**", "/v3/api-docs.yaml"};
        return Stream.of(monitoring, authentication, swagger).flatMap(Stream::of).toArray(String[]::new);
    }

    private String[] getAdminPath() {
        return new String[]{"/admin/**"};
    }

    private String[] getTenancyAdminPath() {
        return new String[]{"/organisation/**"};
    }
}
