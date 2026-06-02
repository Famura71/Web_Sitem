package Aphrodite;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaTypeFactory;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

@RestController
public class AphroditeController {
    private final AphroditeAuthService authService;
    private final AphroditeArchiveSyncService archiveService;

    public AphroditeController(AphroditeAuthService authService,
                               AphroditeArchiveSyncService archiveService) {
        this.authService = authService;
        this.archiveService = archiveService;
    }

    @PostMapping(value = "/api/aphrodite/auth/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        if (request == null || isBlank(request.username()) || isBlank(request.password())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new LoginResponse(false, null, "Missing credentials"));
        }

        AphroditeAuthService.LoginResult result = authService.login(request.username(), request.password());
        if (!result.ok()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new LoginResponse(false, null, result.message()));
        }
        return ResponseEntity.ok(new LoginResponse(true, result.token(), "ok"));
    }

    @GetMapping(value = "/api/aphrodite/archive/root", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ArchiveListResponse> root(@RequestHeader(value = "X-Aphrodite-Token", required = false) String token) {
        if (!authService.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(buildListResponse(""));
    }

    @GetMapping(value = "/api/aphrodite/archive/list", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ArchiveListResponse> list(@RequestHeader(value = "X-Aphrodite-Token", required = false) String token,
                                                    @RequestParam(value = "path", defaultValue = "") String path) {
        if (!authService.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(buildListResponse(path));
    }

    @GetMapping(value = "/api/aphrodite/archive/file")
    public ResponseEntity<Resource> download(@RequestHeader(value = "X-Aphrodite-Token", required = false) String token,
                                             @RequestParam("path") String path) {
        if (!authService.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Path resolved;
        try {
            resolved = archiveService.resolveRelativePath(path);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().build();
        }

        if (!resolved.toFile().isFile()) {
            return ResponseEntity.notFound().build();
        }

        Resource resource = new FileSystemResource(resolved);
        MediaType mediaType = MediaTypeFactory.getMediaType(resolved.getFileName().toString())
                .orElse(MediaType.APPLICATION_OCTET_STREAM);

        ContentDisposition contentDisposition = ContentDisposition.attachment()
                .filename(resolved.getFileName().toString(), StandardCharsets.UTF_8)
                .build();

        return ResponseEntity.ok()
                .contentType(mediaType)
                .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition.toString())
                .body(resource);
    }

    private ArchiveListResponse buildListResponse(String path) {
        String normalized = normalize(path);
        List<AphroditeArchiveSyncService.ArchiveItem> items = archiveService.listChildren(normalized);
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

    private String thumbnailKindFor(AphroditeArchiveSyncService.ArchiveItem item) {
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

    public record LoginRequest(String username, String password) {
    }

    public record LoginResponse(boolean ok, String token, String message) {
    }

    public record ArchiveListResponse(String path, List<ArchiveItemResponse> items) {
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
