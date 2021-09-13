package ru.itpark.security.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import ru.itpark.security.details.ClientDetailsServiceImpl;

public class TokenAuthentication extends AbstractAuthenticationToken {

    private String token;

    public TokenAuthentication(String token) {
        super(ClientDetailsServiceImpl.createGrantedAuthorities());
        this.token = token;
    }

    @Override
    public Object getCredentials() {
        return this.getAuthorities();
    }

    @Override
    public Object getPrincipal() {
        return token;
    }
}
