package ru.itpark.security.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.filter.GenericFilterBean;
import ru.itpark.security.auth.TokenAuthentication;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class TokenAuthFilter extends GenericFilterBean {

    private static final String AUTH_TOKEN = "Auth-Token";

    private AuthenticationManager manager;

    public TokenAuthFilter(AuthenticationManager manager) {
        this.manager = manager;
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        System.out.println(((HttpServletRequest) servletRequest).getRequestURI());
        try {
            String token = extractTokenFromHeaders(httpServletRequest);
            if (token == null) {
                token = extractTokenFromCookies(httpServletRequest);
            }
            if (isNotRequiringProtection(httpServletRequest)) {
                filterChain.doFilter(servletRequest, servletResponse);
            } else if (token == null || token.equals("")) {
                throw new IllegalArgumentException("Token not found");
            } else {
                manager.authenticate(new TokenAuthentication(token));
                filterChain.doFilter(servletRequest, servletResponse);
            }
        } catch (AuthenticationException authenticationException) {
            throw new IllegalArgumentException(authenticationException);
        }
    }

    private boolean isNotRequiringProtection(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String requestMethod = request.getMethod();
        return requestUri.equals("/clients") && requestMethod.equals("POST") ||
                requestUri.equals("/login") && requestMethod.equals("POST") ||
                requestUri.equals("/signup") && requestMethod.equals("GET") ||
                requestUri.equals("/signin") && requestMethod.equals("GET");
    }

    private String extractTokenFromHeaders(HttpServletRequest request) {
        return request.getHeader(AUTH_TOKEN);
    }

    private String extractTokenFromCookies(HttpServletRequest request) {
        Cookie cookies[] = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("Auth-Token")) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
