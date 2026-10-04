package com.paypal.user_service.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JWTrequestFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTrequestFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");

        // No JWT → continue request
        if (authorizationHeader == null ||
                !authorizationHeader.startsWith("Bearer ")) {

            chain.doFilter(request, response);
            return;
        }

        String jwt = authorizationHeader.substring(7);

        // Empty JWT
        if (jwt.isBlank()) {
            chain.doFilter(request, response);
            return;
        }

        try {

            String username = jwtUtil.extractUsername(jwt);

            // Only authenticate if there is no existing authentication
            if (username != null &&
                    SecurityContextHolder.getContext().getAuthentication() == null) {

                // Validate JWT first
                if (jwtUtil.validateToken(jwt, username)) {

                    String role = jwtUtil.extractRole(jwt);

                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    username,
                                    null,
                                    List.of(
                                            new SimpleGrantedAuthority(role)
                                    )
                            );

                    authToken.setDetails(
                            new WebAuthenticationDetailsSource()
                                    .buildDetails(request)
                    );

                    SecurityContextHolder
                            .getContext()
                            .setAuthentication(authToken);
                }
            }

        } catch (Exception e) {

            // Invalid or expired JWT
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }
}