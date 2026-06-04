package Fafnir;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.json.JSONObject;

@Service
public class FafnirSecureService {
    private final FafnirAuthService authService;
    private final FafnirArchiveSyncService archiveService;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, Instant> seenNonces = new ConcurrentHashMap<>();
    private final Map<String, TicketRecord> downloadTickets = new ConcurrentHashMap<>();

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String hmacKey;
    private final long maxSkewSeconds;
    private final long nonceTtlSeconds;

    public FafnirSecureService(FafnirAuthService authService,
                               FafnirArchiveSyncService archiveService,
                               @Value("${fafnir.crypto.rsa-private-key-base64}") String privateKeyBase64,
                               @Value("${fafnir.crypto.hmac-key}") String hmacKey,
                               @Value("${fafnir.crypto.max-skew-seconds:60}") long maxSkewSeconds,
                               @Value("${fafnir.crypto.nonce-ttl-seconds:300}") long nonceTtlSeconds) {
        this.authService = authService;
        this.archiveService = archiveService;
        this.privateKey = loadPrivateKey(privateKeyBase64);
        this.publicKey = derivePublicKey(this.privateKey);
        this.hmacKey = hmacKey;
        this.maxSkewSeconds = maxSkewSeconds;
        this.nonceTtlSeconds = nonceTtlSeconds;
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public JSONObject decryptEnvelope(String payload, String signature) {
        if (payload == null || payload.isBlank() || signature == null || signature.isBlank()) {
            throw new IllegalArgumentException("Missing encrypted payload");
        }

        verifyHmac(payload, signature);
        String json = decryptHybridPayload(payload);
        JSONObject object = new JSONObject(json);
        validateReplayWindow(object);
        return object;
    }

    public DownloadTicket issueTicket(String token, String path) {
        if (!authService.isTokenValid(token)) {
            throw new IllegalArgumentException("Invalid session token");
        }
        String clientPublicKeyBase64 = authService.getClientPublicKey(token);
        if (clientPublicKeyBase64 == null || clientPublicKeyBase64.isBlank()) {
            throw new IllegalArgumentException("Missing client public key");
        }
        String normalized = normalize(path);
        FafnirArchiveSyncService.ArchiveItem item = archiveService.findItem(normalized);
        if (item == null || item.directory()) {
            throw new IllegalArgumentException("File not found");
        }

        String ticket = randomToken();
        Instant expiresAt = Instant.now().plusSeconds(180);
        byte[] aesKey = randomBytes(32);
        byte[] iv = randomBytes(12);
        downloadTickets.put(ticket, new TicketRecord(normalized, expiresAt, token, aesKey, iv));
        cleanupTickets();
        String wrappedAesKey = wrapForClient(clientPublicKeyBase64, aesKey);
        return new DownloadTicket(ticket, expiresAt.toEpochMilli(), wrappedAesKey, Base64.getEncoder().encodeToString(iv));
    }

    public TicketRecord consumeTicket(String ticket) {
        if (ticket == null || ticket.isBlank()) {
            return null;
        }
        cleanupTickets();
        TicketRecord record = downloadTickets.remove(ticket);
        if (record == null || Instant.now().isAfter(record.expiresAt())) {
            return null;
        }
        return record;
    }

    public String readToken(JSONObject payload) {
        String token = payload.optString("token", "");
        if (token.isBlank()) {
            throw new IllegalArgumentException("Missing token");
        }
        if (!authService.isTokenValid(token)) {
            throw new IllegalArgumentException("Invalid session token");
        }
        return token;
    }

    public String readPath(JSONObject payload) {
        return normalize(payload.optString("path", ""));
    }

    public String readUsername(JSONObject payload) {
        return payload.optString("username", "");
    }

    public String readPassword(JSONObject payload) {
        return payload.optString("password", "");
    }

    public String readClientPublicKey(JSONObject payload) {
        return payload.optString("clientPublicKeyBase64", "");
    }

    private void verifyHmac(String payload, String signature) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            byte[] actual = Base64.getDecoder().decode(signature);
            if (!MessageDigest.isEqual(expected, actual)) {
                throw new IllegalArgumentException("Invalid signature");
            }
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Signature validation failed", ex);
        }
    }

    private String decryptHybridPayload(String payload) {
        try {
            byte[] decoded = Base64.getDecoder().decode(payload);
            JSONObject packet = new JSONObject(new String(decoded, StandardCharsets.UTF_8));
            String wrappedKeyBase64 = packet.optString("key", "");
            String ivBase64 = packet.optString("iv", "");
            String dataBase64 = packet.optString("data", "");
            if (wrappedKeyBase64.isBlank() || ivBase64.isBlank() || dataBase64.isBlank()) {
                throw new IllegalArgumentException("Missing packet fields");
            }

            byte[] aesKey = unwrapPayloadKey(wrappedKeyBase64);
            byte[] iv = Base64.getDecoder().decode(ivBase64);
            byte[] ciphertext = Base64.getDecoder().decode(dataBase64);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(aesKey, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(128, iv)
            );
            byte[] plain = cipher.doFinal(ciphertext);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to decrypt secure payload", ex);
        }
    }

    private byte[] unwrapPayloadKey(String wrappedKeyBase64) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    privateKey,
                    new OAEPParameterSpec(
                            "SHA-256",
                            "MGF1",
                            MGF1ParameterSpec.SHA256,
                            PSource.PSpecified.DEFAULT
                    )
            );
            byte[] decoded = Base64.getDecoder().decode(wrappedKeyBase64);
            return cipher.doFinal(decoded);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to unwrap secure payload key", ex);
        }
    }

    private void validateReplayWindow(JSONObject object) {
        String nonce = object.optString("nonce", "");
        long timestamp = object.optLong("timestamp", 0L);
        if (nonce.isBlank() || timestamp <= 0L) {
            throw new IllegalArgumentException("Missing request metadata");
        }

        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - timestamp) > maxSkewSeconds) {
            throw new IllegalArgumentException("Request expired");
        }

        cleanupNonces();
        Instant existing = seenNonces.putIfAbsent(nonce, Instant.now().plusSeconds(nonceTtlSeconds));
        if (existing != null) {
            throw new IllegalArgumentException("Replay detected");
        }
    }

    private void cleanupNonces() {
        Instant now = Instant.now();
        seenNonces.entrySet().removeIf(entry -> now.isAfter(entry.getValue()));
    }

    private void cleanupTickets() {
        Instant now = Instant.now();
        downloadTickets.entrySet().removeIf(entry -> now.isAfter(entry.getValue().expiresAt()));
    }

    private PrivateKey loadPrivateKey(String base64) {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load Fafnir RSA private key", ex);
        }
    }

    private PublicKey derivePublicKey(PrivateKey key) {
        try {
            RSAPrivateCrtKey rsaPrivate = (RSAPrivateCrtKey) key;
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(new RSAPublicKeySpec(rsaPrivate.getModulus(), rsaPrivate.getPublicExponent()));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to derive Fafnir RSA public key", ex);
        }
    }

    private String wrapForClient(String clientPublicKeyBase64, byte[] aesKey) {
        try {
            byte[] decoded = Base64.getDecoder().decode(clientPublicKeyBase64);
            PublicKey clientPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    clientPublicKey,
                    new OAEPParameterSpec(
                            "SHA-256",
                            "MGF1",
                            MGF1ParameterSpec.SHA256,
                            PSource.PSpecified.DEFAULT
                    )
            );
            byte[] wrapped = cipher.doFinal(aesKey);
            return Base64.getEncoder().encodeToString(wrapped);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to wrap download key", ex);
        }
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String normalized = value.replace('\\', '/').trim();
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String randomToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public record DownloadTicket(String ticket, long expiresAtEpochMs, String wrappedAesKeyBase64, String ivBase64) {
    }

    public record TicketRecord(String relativePath, Instant expiresAt, String token, byte[] aesKey, byte[] iv) {
    }
}
