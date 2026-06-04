package Fafnir;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class FafnirAuthService {
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, SessionRecord> sessions = new ConcurrentHashMap<>();

    @Value("${fafnir.login.username:fafnir}")
    private String expectedUsername;

    @Value("${fafnir.login.password:fafnir-2026}")
    private String expectedPassword;

    @Value("${fafnir.session.ttl-seconds:7200}")
    private long sessionTtlSeconds;

    public LoginResult login(String username, String password, String clientPublicKeyBase64) {
        if (!expectedUsername.equals(username) || !expectedPassword.equals(password)) {
            return new LoginResult(false, null, "Invalid credentials");
        }
        if (clientPublicKeyBase64 == null || clientPublicKeyBase64.isBlank()) {
            return new LoginResult(false, null, "Missing client public key");
        }

        cleanupExpiredSessions();
        String token = issueToken();
        sessions.put(token, new SessionRecord(Instant.now().plusSeconds(sessionTtlSeconds), clientPublicKeyBase64));
        return new LoginResult(true, token, "ok");
    }

    public boolean isTokenValid(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }

        cleanupExpiredSessions();
        SessionRecord record = sessions.get(token);
        if (record == null) {
            return false;
        }
        if (Instant.now().isAfter(record.expiresAt())) {
            sessions.remove(token);
            return false;
        }
        return true;
    }

    public String getClientPublicKey(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }

        cleanupExpiredSessions();
        SessionRecord record = sessions.get(token);
        if (record == null || Instant.now().isAfter(record.expiresAt())) {
            sessions.remove(token);
            return null;
        }
        return record.clientPublicKeyBase64();
    }

    private String issueToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private void cleanupExpiredSessions() {
        Instant now = Instant.now();
        sessions.entrySet().removeIf(entry -> now.isAfter(entry.getValue().expiresAt()));
    }

    public record LoginResult(boolean ok, String token, String message) {
    }

    private record SessionRecord(Instant expiresAt, String clientPublicKeyBase64) {
    }
}
