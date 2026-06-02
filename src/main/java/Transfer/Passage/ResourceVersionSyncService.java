package Transfer.Passage;

import Transfer.Hibernate.PrivateResource;
import Transfer.Hibernate.PrivateResourceRepository;
import Transfer.Hibernate.PublicResource;
import Transfer.Hibernate.PublicResourceRepository;
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

    private final ResourceVersionRepository resourceVersionRepository;
    private final PublicResourceRepository publicResourceRepository;
    private final PrivateResourceRepository privateResourceRepository;

    @Value("${resources.public.path:src/main/resources/Database/Public}")
    private String publicPath;

    @Value("${resources.private.path:src/main/resources/Database/Private}")
    private String privatePath;

    public ResourceVersionSyncService(ResourceVersionRepository resourceVersionRepository,
                                      PublicResourceRepository publicResourceRepository,
                                      PrivateResourceRepository privateResourceRepository) {
        this.resourceVersionRepository = resourceVersionRepository;
        this.publicResourceRepository = publicResourceRepository;
        this.privateResourceRepository = privateResourceRepository;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void syncAll() {
        Set<String> publicResources = scanResourceNames(publicPath);
        Set<String> privateResources = scanResourceNames(privatePath);

        syncPublicResources(publicResources);
        syncPrivateResources(privateResources);

        List<ResourceVersion> collected = new ArrayList<>();
        collected.addAll(scanScope("Public", publicPath));
        collected.addAll(scanScope("Private", privatePath));

        Set<String> incomingKeys = collected.stream()
                .map(ResourceVersionSyncService::keyOf)
                .collect(Collectors.toSet());

        List<ResourceVersion> existing = resourceVersionRepository.findAll();
        Set<String> existingKeys = existing.stream()
                .map(ResourceVersionSyncService::keyOf)
                .collect(Collectors.toSet());

        Set<String> toDelete = new HashSet<>(existingKeys);
        toDelete.removeAll(incomingKeys);

        if (!toDelete.isEmpty()) {
            List<ResourceVersion> deleteEntities = existing.stream()
                    .filter(rv -> toDelete.contains(keyOf(rv)))
                    .collect(Collectors.toList());
            resourceVersionRepository.deleteAll(deleteEntities);
        }

        List<ResourceVersion> toInsert = collected.stream()
                .filter(rv -> !existingKeys.contains(keyOf(rv)))
                .collect(Collectors.toList());

        if (!toInsert.isEmpty()) {
            resourceVersionRepository.saveAll(toInsert);
        }

        log.info("resource sync: public={} private={} versions +{} -{}",
                publicResources.size(), privateResources.size(), toInsert.size(), toDelete.size());
    }

    private Set<String> scanResourceNames(String basePath) {
        Path base = Path.of(basePath);
        if (!Files.exists(base) || !Files.isDirectory(base)) {
            log.warn("Resource path not found: {}", basePath);
            return Set.of();
        }

        try (Stream<Path> folders = Files.list(base)) {
            return folders.filter(Files::isDirectory)
                    .map(path -> path.getFileName().toString())
                    .collect(Collectors.toSet());
        } catch (IOException ex) {
            log.warn("Failed scanning resource folders at {}", basePath, ex);
            return Set.of();
        }
    }

    private void syncPublicResources(Set<String> incomingNames) {
        List<PublicResource> existing = publicResourceRepository.findAll();
        Set<String> existingNames = existing.stream()
                .map(PublicResource::getName)
                .collect(Collectors.toSet());

        List<PublicResource> toDelete = existing.stream()
                .filter(resource -> !incomingNames.contains(resource.getName()))
                .collect(Collectors.toList());
        if (!toDelete.isEmpty()) {
            publicResourceRepository.deleteAll(toDelete);
        }

        List<PublicResource> toInsert = incomingNames.stream()
                .filter(name -> !existingNames.contains(name))
                .map(PublicResource::new)
                .collect(Collectors.toList());
        if (!toInsert.isEmpty()) {
            publicResourceRepository.saveAll(toInsert);
        }
    }

    private void syncPrivateResources(Set<String> incomingNames) {
        List<PrivateResource> existing = privateResourceRepository.findAll();
        Set<String> existingNames = existing.stream()
                .map(PrivateResource::getName)
                .collect(Collectors.toSet());

        List<PrivateResource> toDelete = existing.stream()
                .filter(resource -> !incomingNames.contains(resource.getName()))
                .collect(Collectors.toList());
        if (!toDelete.isEmpty()) {
            privateResourceRepository.deleteAll(toDelete);
        }

        List<PrivateResource> toInsert = incomingNames.stream()
                .filter(name -> !existingNames.contains(name))
                .map(PrivateResource::new)
                .collect(Collectors.toList());
        if (!toInsert.isEmpty()) {
            privateResourceRepository.saveAll(toInsert);
        }
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
