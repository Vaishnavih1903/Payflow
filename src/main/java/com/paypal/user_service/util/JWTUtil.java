package com.paypal.user_service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JWTUtil {

    private static final String SECRET =
            "secret123secret123secret123secret123secret123secret123";

    private static final long EXPIRATION_TIME = 86400000; // 1 day

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(
                SECRET.getBytes(StandardCharsets.UTF_8)
        );
    }

    // Generate JWT
    public String generateToken(Long userId, String email, String role) {

        Map<String, Object> claims = new HashMap<>();

        claims.put("userId", userId);
        claims.put("role", role);

        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(new Date())
                .expiration(
                        new Date(System.currentTimeMillis() + EXPIRATION_TIME)
                )
                .signWith(getSigningKey())
                .compact();
    }

    // Extract all claims
    public Claims extractAllClaims(String token) {

        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // Extract email
    public String extractEmail(String token) {

        return extractAllClaims(token)
                .getSubject();
    }

    // Extract username
    public String extractUsername(String token) {

        return extractEmail(token);
    }

    // Extract role
    public String extractRole(String token) {

        return extractAllClaims(token)
                .get("role", String.class);
    }

    // Extract user ID
    public Long extractUserId(String token) {

        return extractAllClaims(token)
                .get("userId", Long.class);
    }

    // Validate token
    public boolean validateToken(String token, String email) {

        try {

            String tokenEmail = extractEmail(token);

            return tokenEmail.equals(email)
                    && !isTokenExpired(token);

        } catch (Exception e) {

            return false;
        }
    }

    // Check expiration
    private boolean isTokenExpired(String token) {

        return extractAllClaims(token)
                .getExpiration()
                .before(new Date());
    }
}