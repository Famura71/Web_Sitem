package Fafnir;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

@Service
public class FafnirArchiveSyncService {
    private static final Logger log = LoggerFactory.getLogger(FafnirArchiveSyncService.class);

    @Value("${fafnir.archive.root-path:src/main/resources/Archive}")
    private String archiveRootPath;

    @Value("${fafnir.db.path:./Fafnir.db}")
    private String databasePath;

    @EventListener(ApplicationReadyEvent.class)
    public void syncOnStartup() {
        sync();
    }

    public synchronized void sync() {
        Path root = Path.of(archiveRootPath).toAbsolutePath().normalize();
        try {
            Files.createDirectories(root);
        } catch (IOException ex) {
            log.warn("Failed to create Fafnir archive root: {}", root, ex);
        }

        ensureSchemaQuietly();

        List<ArchiveRow> rows = scan(root);
        Set<String> incomingPaths = new HashSet<>();
        for (ArchiveRow row : rows) {
            incomingPaths.add(row.relativePath);
        }

        try (Connection connection = openConnection()) {
            connection.setAutoCommit(false);

            Set<String> existingPaths = new HashSet<>();
            try (Statement statement = connection.createStatement();
                 ResultSet resultSet = statement.executeQuery("SELECT relative_path FROM archive_items")) {
                while (resultSet.next()) {
                    existingPaths.add(resultSet.getString(1));
                }
            }

            Set<String> toDelete = new HashSet<>(existingPaths);
            toDelete.removeAll(incomingPaths);
            if (!toDelete.isEmpty()) {
                try (PreparedStatement delete = connection.prepareStatement("DELETE FROM archive_items WHERE relative_path = ?")) {
                    for (String path : toDelete) {
                        delete.setString(1, path);
                        delete.addBatch();
                    }
                    delete.executeBatch();
                }
            }

            String sql = """
                    INSERT INTO archive_items (
                        relative_path, parent_path, name, directory, mime_type, size_bytes, last_modified_epoch_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(relative_path) DO UPDATE SET
                        parent_path = excluded.parent_path,
                        name = excluded.name,
                        directory = excluded.directory,
                        mime_type = excluded.mime_type,
                        size_bytes = excluded.size_bytes,
                        last_modified_epoch_ms = excluded.last_modified_epoch_ms
                    """;
            try (PreparedStatement upsert = connection.prepareStatement(sql)) {
                for (ArchiveRow row : rows) {
                    upsert.setString(1, row.relativePath);
                    upsert.setString(2, row.parentPath);
                    upsert.setString(3, row.name);
                    upsert.setInt(4, row.directory ? 1 : 0);
                    upsert.setString(5, row.mimeType);
                    upsert.setLong(6, row.sizeBytes);
                    upsert.setLong(7, row.lastModifiedEpochMs);
                    upsert.addBatch();
                }
                upsert.executeBatch();
            }

            connection.commit();
            log.info("Fafnir archive sync complete. items={}", rows.size());
        } catch (Exception ex) {
            log.warn("Fafnir archive sync failed", ex);
        }
    }

    public List<ArchiveItem> listChildren(String parentPath) {
        ensureSchemaQuietly();
        String normalizedParent = normalizeRelative(parentPath);
        List<ArchiveItem> items = new ArrayList<>();

        String sql = """
                SELECT relative_path, parent_path, name, directory, mime_type, size_bytes, last_modified_epoch_ms
                FROM archive_items
                WHERE parent_path = ?
                ORDER BY directory DESC, name COLLATE NOCASE ASC
                """;

        try (Connection connection = openConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, normalizedParent);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    items.add(mapRow(resultSet));
                }
            }
        } catch (Exception ex) {
            log.warn("Fafnir archive list failed for parent={}", normalizedParent, ex);
        }

        return items;
    }

    public ArchiveItem findItem(String relativePath) {
        ensureSchemaQuietly();
        String normalized = normalizeRelative(relativePath);
        String sql = """
                SELECT relative_path, parent_path, name, directory, mime_type, size_bytes, last_modified_epoch_ms
                FROM archive_items
                WHERE relative_path = ?
                """;

        try (Connection connection = openConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, normalized);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return mapRow(resultSet);
                }
            }
        } catch (Exception ex) {
            log.warn("Fafnir archive lookup failed for path={}", normalized, ex);
        }
        return null;
    }

    public Path resolveRelativePath(String relativePath) {
        Path root = Path.of(archiveRootPath).toAbsolutePath().normalize();
        String normalized = normalizeRelative(relativePath);
        Path resolved = root.resolve(normalized.replace("/", root.getFileSystem().getSeparator())).normalize();
        if (!resolved.startsWith(root)) {
            throw new IllegalArgumentException("Invalid archive path");
        }
        return resolved;
    }

    private List<ArchiveRow> scan(Path root) {
        List<ArchiveRow> rows = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(root)) {
            stream.forEach(path -> {
                if (path.equals(root)) {
                    return;
                }
                Path rel = root.relativize(path);
                String relativePath = normalizeRelative(rel.toString());
                String parentPath = normalizeRelative(rel.getParent() == null ? "" : rel.getParent().toString());
                String name = path.getFileName().toString();
                boolean directory = Files.isDirectory(path);
                long sizeBytes = 0L;
                long modified = 0L;
                try {
                    if (!directory) {
                        sizeBytes = Files.size(path);
                    }
                    modified = Files.getLastModifiedTime(path).toMillis();
                } catch (IOException ignored) {
                    // Best effort metadata.
                }
                rows.add(new ArchiveRow(
                        relativePath,
                        parentPath,
                        name,
                        directory,
                        resolveMimeType(path, directory),
                        sizeBytes,
                        modified
                ));
            });
        } catch (IOException ex) {
            log.warn("Fafnir archive scan failed at {}", root, ex);
        }
        return rows;
    }

    private ArchiveItem mapRow(ResultSet resultSet) throws Exception {
        return new ArchiveItem(
                resultSet.getString("relative_path"),
                resultSet.getString("parent_path"),
                resultSet.getString("name"),
                resultSet.getInt("directory") == 1,
                resultSet.getString("mime_type"),
                resultSet.getLong("size_bytes"),
                resultSet.getLong("last_modified_epoch_ms")
        );
    }

    private Connection openConnection() throws Exception {
        String absolute = Path.of(databasePath).toAbsolutePath().normalize().toString().replace('\\', '/');
        return DriverManager.getConnection("jdbc:sqlite:" + absolute);
    }

    private void ensureSchemaQuietly() {
        try (Connection connection = openConnection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS archive_items (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        relative_path TEXT NOT NULL UNIQUE,
                        parent_path TEXT NOT NULL,
                        name TEXT NOT NULL,
                        directory INTEGER NOT NULL,
                        mime_type TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL,
                        last_modified_epoch_ms INTEGER NOT NULL
                    )
                    """);
        } catch (Exception ex) {
            log.warn("Fafnir archive schema init failed", ex);
        }
    }

    private String resolveMimeType(Path path, boolean directory) {
        if (directory) {
            return "inode/directory";
        }
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".mp3")) {
            return "audio/mpeg";
        }
        if (name.endsWith(".mp4")) {
            return "video/mp4";
        }
        return "application/octet-stream";
    }

    private static String normalizeRelative(String value) {
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

    private record ArchiveRow(
            String relativePath,
            String parentPath,
            String name,
            boolean directory,
            String mimeType,
            long sizeBytes,
            long lastModifiedEpochMs
    ) {
    }

    public record ArchiveItem(
            String relativePath,
            String parentPath,
            String name,
            boolean directory,
            String mimeType,
            long sizeBytes,
            long lastModifiedEpochMs
    ) {
    }
}
