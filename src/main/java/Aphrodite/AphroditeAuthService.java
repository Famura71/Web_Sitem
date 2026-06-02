package Aphrodite;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AphroditeAuthService {
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, Instant> sessions = new ConcurrentHashMap<>();

    @Value("${aphrodite.login.username:aphrodite}")
    private String expectedUsername;

    @Value("${aphrodite.login.password:aphrodite-2026}")
    private String expectedPassword;

    @Value("${aphrodite.session.ttl-seconds:7200}")
    private long sessionTtlSeconds;

    public LoginResult login(String username, String password) {
        if (!expectedUsername.equals(username) || !expectedPassword.equals(password)) {
            return new LoginResult(false, null, "Invalid credentials");
        }

        cleanupExpiredSessions();
        String token = issueToken();
        sessions.put(token, Instant.now().plusSeconds(sessionTtlSeconds));
        return new LoginResult(true, token, "ok");
    }

    public boolean isTokenValid(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }

        cleanupExpiredSessions();
        Instant expiresAt = sessions.get(token);
        if (expiresAt == null) {
            return false;
        }
        if (Instant.now().isAfter(expiresAt)) {
            sessions.remove(token);
            return false;
        }
        return true;
    }

    private String issueToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private void cleanupExpiredSessions() {
        Instant now = Instant.now();
        sessions.entrySet().removeIf(entry -> now.isAfter(entry.getValue()));
    }

    public record LoginResult(boolean ok, String token, String message) {
    }
}
