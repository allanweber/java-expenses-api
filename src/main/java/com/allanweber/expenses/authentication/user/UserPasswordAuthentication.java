package com.allanweber.expenses.authentication.user;

import com.allanweber.expenses.authentication.UserPasswordAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class UserPasswordAuthentication implements UserPasswordAuthenticationManager {
    @Override
    public Authentication authenticate(Authentication authentication) {
        return null;
    }
}
