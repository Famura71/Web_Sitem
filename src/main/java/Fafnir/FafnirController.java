package Fafnir;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

@RestController
public class FafnirController {
    private static final Logger log = LoggerFactory.getLogger(FafnirController.class);
    private final FafnirAuthService authService;
    private final FafnirArchiveSyncService archiveService;
    private final FafnirSecureService secureService;

    public FafnirController(FafnirAuthService authService,
                            FafnirArchiveSyncService archiveService,
                            FafnirSecureService secureService) {
        this.authService = authService;
        this.archiveService = archiveService;
        this.secureService = secureService;
    }

    @GetMapping(value = "/api/fafnir/crypto/public-key", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<PublicKeyResponse> publicKey() {
        return ResponseEntity.ok(new PublicKeyResponse("RSA", secureService.getPublicKeyBase64()));
    }

    @PostMapping(value = "/api/fafnir/auth/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LoginResponse> login(@RequestBody SecureEnvelopeRequest request) {
        if (request == null || isBlank(request.payload()) || isBlank(request.signature())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new LoginResponse(false, null, "Missing secure payload"));
        }

        final org.json.JSONObject payload;
        try {
            payload = secureService.decryptEnvelope(request.payload(), request.signature());
        } catch (IllegalArgumentException ex) {
            log.warn("Fafnir login secure payload rejected: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new LoginResponse(false, null, "Invalid secure payload"));
        }

        String username;
        String password;
        try {
            username = secureService.readUsername(payload);
            password = secureService.readPassword(payload);
            String clientPublicKey = request.clientPublicKeyBase64();
            if (isBlank(clientPublicKey)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new LoginResponse(false, null, "Missing client public key"));
            }
            FafnirAuthService.LoginResult result = authService.login(username, password, clientPublicKey);
            if (!result.ok()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new LoginResponse(false, null, result.message()));
            }
            return ResponseEntity.ok(new LoginResponse(true, result.token(), "ok"));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new LoginResponse(false, null, "Missing credentials"));
        }
    }

    @PostMapping(value = "/api/fafnir/archive/list", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ArchiveListResponse> list(@RequestBody SecureEnvelopeRequest request) {
        if (request == null || isBlank(request.payload()) || isBlank(request.signature())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        final org.json.JSONObject payload;
        try {
            payload = secureService.decryptEnvelope(request.payload(), request.signature());
        } catch (IllegalArgumentException ex) {
            log.warn("Fafnir archive list secure payload rejected: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        final String token;
        final String path;
        try {
            token = secureService.readToken(payload);
            path = secureService.readPath(payload);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!authService.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(buildListResponse(path));
    }

    @PostMapping(value = "/api/fafnir/archive/ticket", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<DownloadTicketResponse> ticket(@RequestBody SecureEnvelopeRequest request) {
        if (request == null || isBlank(request.payload()) || isBlank(request.signature())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        final org.json.JSONObject payload;
        try {
            payload = secureService.decryptEnvelope(request.payload(), request.signature());
        } catch (IllegalArgumentException ex) {
            log.warn("Fafnir archive ticket secure payload rejected: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        final String token;
        final String path;
        try {
            token = secureService.readToken(payload);
            path = secureService.readPath(payload);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!authService.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        FafnirSecureService.DownloadTicket ticket;
        try {
            ticket = secureService.issueTicket(token, path);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(new DownloadTicketResponse(
                ticket.ticket(),
                ticket.expiresAtEpochMs(),
                ticket.wrappedAesKeyBase64(),
                ticket.ivBase64()
        ));
    }

    @GetMapping(value = "/api/fafnir/archive/file")
    public ResponseEntity<StreamingResponseBody> download(@RequestParam("ticket") String ticket) {
        FafnirSecureService.TicketRecord record = secureService.consumeTicket(ticket);
        if (record == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Path resolved;
        try {
            resolved = archiveService.resolveRelativePath(record.relativePath());
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().build();
        }

        if (!resolved.toFile().isFile()) {
            return ResponseEntity.notFound().build();
        }

        FafnirArchiveSyncService.ArchiveItem item = archiveService.findItem(record.relativePath());
        String originalMimeType = item == null ? "application/octet-stream" : item.mimeType();

        ContentDisposition contentDisposition = ContentDisposition.attachment()
                .filename(resolved.getFileName().toString(), StandardCharsets.UTF_8)
                .build();

        StreamingResponseBody body = outputStream -> {
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(record.aesKey(), "AES"),
                        new GCMParameterSpec(128, record.iv())
                );
                try (InputStream input = java.nio.file.Files.newInputStream(resolved);
                     CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
                    input.transferTo(cipherOutputStream);
                }
            } catch (Exception ex) {
                throw new IllegalStateException("Failed to stream encrypted archive file", ex);
            }
        };

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition.toString())
                .header("X-Fafnir-Content-Encryption", "AES/GCM/NoPadding")
                .header("X-Fafnir-Content-IV", Base64.getEncoder().encodeToString(record.iv()))
                .header("X-Fafnir-Content-Original-MimeType", originalMimeType)
                .body(body);
    }

    private ArchiveListResponse buildListResponse(String path) {
        String normalized = normalize(path);
        List<FafnirArchiveSyncService.ArchiveItem> items = archiveService.listChildren(normalized);
        List<ArchiveItemResponse> mapped = items.stream()
                .map(item -> new ArchiveItemResponse(
                        item.relativePath(),
                        item.parentPath(),
                        item.name(),
                        item.directory(),
                        item.mimeType(),
                        item.sizeBytes(),
                        item.lastModifiedEpochMs(),
                        thumbnailKindFor(item)
                ))
                .toList();
        return new ArchiveListResponse(normalized, mapped);
    }

    private String thumbnailKindFor(FafnirArchiveSyncService.ArchiveItem item) {
        if (item.directory()) {
            return "folder";
        }
        String mime = item.mimeType() == null ? "" : item.mimeType().toLowerCase();
        if (mime.startsWith("audio/")) {
            return "audio";
        }
        if (mime.startsWith("video/")) {
            return "video";
        }
        return "file";
    }

    private static String normalize(String value) {
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

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public record SecureEnvelopeRequest(String payload, String signature, String clientPublicKeyBase64) {
    }

    public record LoginResponse(boolean ok, String token, String message) {
    }

    public record ArchiveListResponse(String path, List<ArchiveItemResponse> items) {
    }

    public record PublicKeyResponse(String algorithm, String publicKeyBase64) {
    }

    public record DownloadTicketResponse(String ticket, long expiresAtEpochMs, String wrappedAesKeyBase64, String ivBase64) {
    }

    public record ArchiveItemResponse(
            String relativePath,
            String parentPath,
            String name,
            boolean directory,
            String mimeType,
            long sizeBytes,
            long lastModifiedEpochMs,
            String thumbnailKind
    ) {
    }
}
