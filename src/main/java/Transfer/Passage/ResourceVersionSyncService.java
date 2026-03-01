package Transfer.Passage;

import Transfer.Hibernate.ResourceVersion;
import Transfer.Hibernate.ResourceVersionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class ResourceVersionSyncService {
    private static final Logger log = LoggerFactory.getLogger(ResourceVersionSyncService.class);

    private final ResourceVersionRepository repo;

    @Value("${resources.public.path:src/main/resources/Database/Public}")
    private String publicPath;

    @Value("${resources.private.path:src/main/resources/Database/Private}")
    private String privatePath;

    public ResourceVersionSyncService(ResourceVersionRepository repo) {
        this.repo = repo;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void syncAll() {
        List<ResourceVersion> collected = new ArrayList<>();
        collected.addAll(scanScope("Public", publicPath));
        collected.addAll(scanScope("Private", privatePath));

        if (collected.isEmpty()) {
            return;
        }

        Set<String> incomingKeys = collected.stream()
                .map(ResourceVersionSyncService::keyOf)
                .collect(Collectors.toSet());

        List<ResourceVersion> existing = repo.findAll();
        Set<String> existingKeys = existing.stream()
                .map(ResourceVersionSyncService::keyOf)
                .collect(Collectors.toSet());

        Set<String> toDelete = new HashSet<>(existingKeys);
        toDelete.removeAll(incomingKeys);

        if (!toDelete.isEmpty()) {
            List<ResourceVersion> deleteEntities = existing.stream()
                    .filter(rv -> toDelete.contains(keyOf(rv)))
                    .collect(Collectors.toList());
            repo.deleteAll(deleteEntities);
        }

        List<ResourceVersion> toInsert = collected.stream()
                .filter(rv -> !existingKeys.contains(keyOf(rv)))
                .collect(Collectors.toList());

        if (!toInsert.isEmpty()) {
            repo.saveAll(toInsert);
        }

        log.info("resources_versions sync: +{} -{}", toInsert.size(), toDelete.size());
    }

    private List<ResourceVersion> scanScope(String scope, String basePath) {
        Path base = Path.of(basePath);
        if (!Files.exists(base) || !Files.isDirectory(base)) {
            log.warn("Resource version path not found: {}", basePath);
            return List.of();
        }

        List<ResourceVersion> out = new ArrayList<>();
        try (Stream<Path> folders = Files.list(base)) {
            for (Path folder : folders.filter(Files::isDirectory).toList()) {
                String klasor = folder.getFileName().toString();
                try (Stream<Path> files = Files.list(folder)) {
                    for (Path file : files.filter(Files::isRegularFile).toList()) {
                        String isim = file.getFileName().toString();
                        ParsedName parsed = parseName(isim);
                        if (parsed == null) {
                            continue;
                        }
                        out.add(new ResourceVersion(klasor, isim, scope, parsed.version, parsed.uploader));
                    }
                }
            }
        } catch (IOException ex) {
            log.warn("Failed scanning resources_versions at {}", basePath, ex);
        }
        return out;
    }

    private static ParsedName parseName(String isim) {
        int idx = isim.indexOf('_');
        if (idx <= 0 || idx == isim.length() - 1) {
            return null;
        }
        String version = isim.substring(0, idx).trim();
        String uploaderPart = isim.substring(idx + 1).trim();
        if (version.isEmpty() || uploaderPart.isEmpty()) {
            return null;
        }
        String uploader = uploaderPart;
        int dot = uploaderPart.lastIndexOf('.');
        if (dot > 0) {
            uploader = uploaderPart.substring(0, dot).trim();
        }
        return new ParsedName(version, uploader);
    }

    private static String keyOf(ResourceVersion rv) {
        return rv.getScope() + "|" + rv.getKlasor() + "|" + rv.getIsim();
    }

    private record ParsedName(String version, String uploader) {}
}
