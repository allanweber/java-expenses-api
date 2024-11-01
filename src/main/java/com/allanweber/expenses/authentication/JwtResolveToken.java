package com.allanweber.expenses.authentication;

import jakarta.servlet.http.HttpServletRequest;

public interface JwtResolveToken {
    String resolve(HttpServletRequest request);
}
