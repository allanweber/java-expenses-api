package com.allanweber.expenses.authentication.token;

import com.allanweber.expenses.authentication.AccessTokenInfo;
import com.allanweber.expenses.authentication.JwtResolveToken;
import com.allanweber.expenses.authentication.JwtTokenReader;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.lang.NonNull;

@Component
public class AccessTokenResolver implements HandlerMethodArgumentResolver {

    private final JwtTokenReader tokenReader;
    private final JwtResolveToken resolveToken;

    public AccessTokenResolver(JwtTokenReader tokenReader, JwtResolveToken resolveToken) {
        this.tokenReader = tokenReader;
        this.resolveToken = resolveToken;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterType().equals(AccessTokenInfo.class);
    }

    @Override
    public Object resolveArgument(@NonNull MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        String token = resolveToken.resolve(request);
        return tokenReader.getAccessTokenInfo(token);
    }
}
