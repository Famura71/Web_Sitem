package Transfer.Passage;

import Transfer.Hibernate.Kisi;
import Transfer.Hibernate.KisiRepository;
import Transfer.Hibernate.ResourceVersion;
import Transfer.Hibernate.ResourceVersionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

@RestController
public class Passage_Controller {
    private static final Logger log = LoggerFactory.getLogger(Passage_Controller.class);
    private final KisiRepository kisiRepository;
    private final ResourceVersionRepository resourceVersionRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AtomicReference<PullState> lastPull = new AtomicReference<>(null);
    private final AtomicReference<PushState> lastPush = new AtomicReference<>(null);

    @Value("${private.api.rsa-private-key-base64:}")
    private String rsaPrivateKeyBase64;

    @Value("${private.api.hmac-key:}")
    private String hmacKey;

    @Value("${resources.public.path:src/main/resources/Database/Public}")
    private String publicPath;

    @Value("${resources.private.path:src/main/resources/Database/Private}")
    private String privatePath;

    public Passage_Controller(KisiRepository kisiRepository,
                              ResourceVersionRepository resourceVersionRepository) {
        this.kisiRepository = kisiRepository;
        this.resourceVersionRepository = resourceVersionRepository;
    }

    @PostMapping(value = "/api/private/transfer", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> controller(@RequestBody byte[] payload) {
        String result = receive_file(payload);
        return ResponseEntity.ok(result.getBytes(StandardCharsets.UTF_8));
    }

    @PostMapping(value = "/api/private/transfer/json", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> send_file_json(@RequestParam("name") String name, @RequestBody String jsonPayload) {
        return ResponseEntity.badRequest().build();
    }

    @PostMapping(value = "/api/private/transfer/zip", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> send_file_zip(@RequestBody String ignored) {
        PullState state = lastPull.get();
        if (state == null) {
            return ResponseEntity.badRequest().build();
        }
        try {
            Path file = Path.of(state.filePath);
            if (!Files.exists(file) || !Files.isRegularFile(file)) {
                return ResponseEntity.notFound().build();
            }
            byte[] data = Files.readAllBytes(file);
            String encrypted = encrypt_aes_gcm(data, state.aesKey);
            return ResponseEntity.ok(encrypted.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            return ResponseEntity.status(500).build();
        }
    }

    @PostMapping(value = "/api/private/transfer/pushzip", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> receive_push_zip(@RequestBody byte[] payload) {
        PushState state = lastPush.getAndSet(null);
        if (state == null) {
            return ResponseEntity.badRequest().build();
        }
        try {
            byte[] zipBytes = decrypt_aes_gcm(payload, state.aesKey);
            String version = currentVersionString();
            String fileName = version + " _ " + state.uploader + ".zip";
            String basePath = "Public".equalsIgnoreCase(state.scope) ? publicPath : privatePath;
            Path target = Path.of(basePath, state.klasor, fileName);
            Files.createDirectories(target.getParent());
            Files.write(target, zipBytes);
            ResourceVersion rv = new ResourceVersion(state.klasor, state.klasor, state.scope, version, state.uploader);
            resourceVersionRepository.save(rv);
            return ResponseEntity.ok("0".getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            return ResponseEntity.ok("2".getBytes(StandardCharsets.UTF_8));
        }
    }

    private String receive_file(byte[] payload) {
        if (payload == null || payload.length == 0) {
            log.warn("receive_file: missing payload");
            return "1";
        }
        String raw = new String(payload, StandardCharsets.UTF_8);
        int sep = raw.lastIndexOf('|');
        if (sep <= 0 || sep == raw.length() - 1) {
            log.warn("receive_file: invalid signed payload");
            return "1";
        }
        String encryptedPart = raw.substring(0, sep);
        String signaturePart = raw.substring(sep + 1);
        log.warn("receive_file: encryptedPart(base64)={}", encryptedPart);
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getDecoder().decode(signaturePart);
        } catch (IllegalArgumentException ex) {
            log.warn("receive_file: signature base64 decode failed");
            return "1";
        }
        try {
            boolean ok = verify_signature(encryptedPart.getBytes(StandardCharsets.UTF_8), signatureBytes);
            if (!ok) {
                log.warn("receive_file: signature mismatch");
                return "1";
            }
        } catch (Exception ex) {
            log.warn("receive_file: signature verification failed");
            return "1";
        }
        log.warn("receive_file: rsa key length={}", (rsaPrivateKeyBase64 == null ? -1 : rsaPrivateKeyBase64.length()));
        String decrypted;
        try {
            decrypted = rsa_decrypt(encryptedPart);
        } catch (Exception ex) {
            log.warn("receive_file: rsa decrypt failed");
            return "2";
        }

        RequestPayload request;
        try {
            request = objectMapper.readValue(decrypted, RequestPayload.class);
        } catch (Exception ex) {
            log.warn("receive_file: json parse failed");
            return "2";
        }

        if (request.request == null || request.request.isBlank()
                || request.name == null || request.name.isBlank()) {
            log.warn("receive_file: missing request or name");
            return "2";
        }

        return switch (request.request) {
            case "login" -> handle_login(request);
            case "connect" -> handle_connect(request);
            case "check" -> handle_check(request);
            case "pull" -> handle_pull(request);
            case "manage" -> handle_manage(request);
            case "push" -> handle_push(request);
            default -> "2";
        };
    }

    private String handle_login(RequestPayload req) {
        if (req.password == null || req.password.isBlank()) {
            return "2";
        }
        Optional<Kisi> kisiOpt = kisiRepository.findByAd(req.name);
        if (kisiOpt.isEmpty()) {
            return "3";
        }
        Kisi kisi = kisiOpt.get();
        if (!req.password.equals(kisi.getSifre())) {
            return "4";
        }
        String json = "{\"name\":\"" + escape_json(kisi.getAd()) + "\",\"yetki\":" + kisi.getYetkiSeviyesi() + "}";
        return "0|" + json;
    }

    private String handle_connect(RequestPayload req) {
        if (req.data == null || req.data.isBlank()) {
            return "2";
        }
        if (req.password == null || req.password.isBlank()) {
            return "2";
        }
        Optional<Kisi> kisiOpt = kisiRepository.findByAd(req.name);
        if (kisiOpt.isEmpty()) {
            return "3";
        }
        Kisi kisi = kisiOpt.get();
        if (!req.password.equals(kisi.getSifre())) {
            return "4";
        }

        String[] parts = req.data.split("/", 2);
        if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
            return "2";
        }
        String scope = parts[0];
        String resource = parts[1];

        if ("Public".equalsIgnoreCase(scope)) {
            boolean exists = !resourceVersionRepository
                    .findAllByScopeIgnoreCaseAndKlasor("Public", resource).isEmpty();
            if (!exists) {
                return "5";
            }
            if (!canPublicPull(kisi.getYetkiSeviyesi())) {
                return "6";
            }
            return "0";
        }

        if ("Private".equalsIgnoreCase(scope)) {
            boolean exists = !resourceVersionRepository
                    .findAllByScopeIgnoreCaseAndKlasor("Private", resource).isEmpty();
            if (!exists) {
                return "5";
            }
            if (!canPrivatePull(kisi.getYetkiSeviyesi())) {
                return "6";
            }
            return "0";
        }

        return "2";
    }

    private String handle_check(RequestPayload req) {
        if (req.data == null || req.data.isBlank()) {
            return "2";
        }
        if (req.password == null || req.password.isBlank()) {
            return "2";
        }
        Optional<Kisi> kisiOpt = kisiRepository.findByAd(req.name);
        if (kisiOpt.isEmpty()) {
            return "3";
        }
        Kisi kisi = kisiOpt.get();
        if (!req.password.equals(kisi.getSifre())) {
            return "4";
        }

        String[] parts = req.data.split("/", 2);
        if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
            return "2";
        }
        String scope = parts[0];
        String resource = parts[1];

        List<ResourceVersion> versions;
        if ("Public".equalsIgnoreCase(scope)) {
            if (!canPublicPull(kisi.getYetkiSeviyesi())) {
                return "6";
            }
            versions = resourceVersionRepository.findAllByScopeIgnoreCaseAndKlasor("Public", resource);
        } else if ("Private".equalsIgnoreCase(scope)) {
            if (!canPrivatePull(kisi.getYetkiSeviyesi())) {
                return "6";
            }
            versions = resourceVersionRepository.findAllByScopeIgnoreCaseAndKlasor("Private", resource);
        } else {
            return "2";
        }

        if (versions.isEmpty()) {
            return "5";
        }

        List<String> versionList = versions.stream()
                .map(ResourceVersion::getVersiyon)
                .distinct()
                .sorted()
                .toList();
        try {
            String json = objectMapper.writeValueAsString(versionList);
            return "0|" + json;
        } catch (Exception ex) {
            return "2";
        }
    }

    private String handle_pull(RequestPayload req) {
        if (req.data == null || req.data.isBlank()) {
            return "2";
        }
        if (req.password == null || req.password.isBlank()) {
            return "2";
        }
        Optional<Kisi> kisiOpt = kisiRepository.findByAd(req.name);
        if (kisiOpt.isEmpty()) {
            return "3";
        }
        Kisi kisi = kisiOpt.get();
        if (!req.password.equals(kisi.getSifre())) {
            return "4";
        }

        String[] parts = req.data.split("/", 3);
        if (parts.length < 2 || parts[0].isBlank() || parts[1].isBlank()) {
            return "2";
        }
        String scope = parts[0];
        String resource = parts[1];
        String requestedVersion = parts.length == 3 ? parts[2].trim() : "";

        List<ResourceVersion> versions;
        if ("Public".equalsIgnoreCase(scope)) {
            if (!canPublicPull(kisi.getYetkiSeviyesi())) {
                return "6";
            }
            versions = resourceVersionRepository.findAllByScopeIgnoreCaseAndKlasor("Public", resource);
        } else if ("Private".equalsIgnoreCase(scope)) {
            if (!canPrivatePull(kisi.getYetkiSeviyesi())) {
                return "6";
            }
            versions = resourceVersionRepository.findAllByScopeIgnoreCaseAndKlasor("Private", resource);
        } else {
            return "2";
        }

        if (versions.isEmpty()) {
            return "5";
        }

        ResourceVersion chosen;
        if (requestedVersion != null && !requestedVersion.isBlank()) {
            chosen = versions.stream()
                    .filter(v -> requestedVersion.equals(v.getVersiyon()))
                    .findFirst()
                    .orElse(null);
            if (chosen == null) {
                return "5";
            }
        } else {
            chosen = versions.stream()
                    .max((a, b) -> compareVersionDate(a.getVersiyon(), b.getVersiyon()))
                    .orElse(null);
            if (chosen == null) {
                return "5";
            }
        }

        String fileName = chosen.getVersiyon() + " _ " + chosen.getYukleyen() + ".zip";
        String basePath = "Public".equalsIgnoreCase(scope) ? publicPath : privatePath;
        String filePath = Path.of(basePath, resource, fileName).toString();

        byte[] aesKey = generate_aes_key();
        lastPull.set(new PullState(filePath, aesKey));

        String json = "{\"response\":\"0 aes key : " + Base64.getEncoder().encodeToString(aesKey) + "\"}";
        try {
            return send_file_json_internal(req.name, json);
        } catch (Exception ex) {
            return "2";
        }
    }

    private String handle_push(RequestPayload req) {
        if (req.data == null || req.data.isBlank()) {
            return "2";
        }
        if (req.password == null || req.password.isBlank()) {
            return "2";
        }
        Optional<Kisi> kisiOpt = kisiRepository.findByAd(req.name);
        if (kisiOpt.isEmpty()) {
            return "3";
        }
        Kisi kisi = kisiOpt.get();
        if (!req.password.equals(kisi.getSifre())) {
            return "4";
        }

        String[] parts = req.data.split("/", 3);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
            return "2";
        }
        String scope = parts[0];
        String klasor = parts[1];
        String aesKeyRaw = parts[2];

        if ("Public".equalsIgnoreCase(scope)) {
            if (!canPublicPush(kisi.getYetkiSeviyesi())) {
                return "6";
            }
        } else if ("Private".equalsIgnoreCase(scope)) {
            if (!canPrivatePush(kisi.getYetkiSeviyesi())) {
                return "6";
            }
        } else {
            return "2";
        }

        byte[] aesKey;
        try {
            aesKey = Base64.getDecoder().decode(aesKeyRaw);
        } catch (IllegalArgumentException ex) {
            aesKey = aesKeyRaw.getBytes(StandardCharsets.UTF_8);
        }

        lastPush.set(new PushState(scope, klasor, aesKey, req.name));
        return "0";
    }

    private String handle_manage(RequestPayload req) {
        if (req.data == null || req.data.isBlank()) {
            return "2";
        }
        if (req.password == null || req.password.isBlank()) {
            return "2";
        }
        Optional<Kisi> kisiOpt = kisiRepository.findByAd(req.name);
        if (kisiOpt.isEmpty()) {
            return "3";
        }
        Kisi kisi = kisiOpt.get();
        if (!req.password.equals(kisi.getSifre())) {
            return "4";
        }

        String[] parts = req.data.split("/", 3);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
            return "2";
        }
        String scope = parts[0];
        String klasor = parts[1];
        String versiyon = parts[2];

        if ("Public".equalsIgnoreCase(scope)) {
            if (!canPublicManage(kisi.getYetkiSeviyesi())) {
                return "6";
            }
        } else if ("Private".equalsIgnoreCase(scope)) {
            if (!canPrivateManage(kisi.getYetkiSeviyesi())) {
                return "6";
            }
        } else {
            return "2";
        }

        List<ResourceVersion> matches =
                resourceVersionRepository.findAllByScopeIgnoreCaseAndKlasorAndVersiyon(scope, klasor, versiyon);
        if (matches.isEmpty()) {
            return "5";
        }

        ResourceVersion rv = matches.get(0);
        String fileName = rv.getVersiyon() + " _ " + rv.getYukleyen() + ".zip";
        String basePath = "Public".equalsIgnoreCase(scope) ? publicPath : privatePath;
        Path target = Path.of(basePath, klasor, fileName);
        try {
            Files.deleteIfExists(target);
        } catch (Exception ex) {
            return "2";
        }

        resourceVersionRepository.deleteAll(matches);
        return "0";
    }

    private String send_file_json_internal(String name, String jsonPayload) throws Exception {
        String encrypted = rsa_encrypt(jsonPayload, name);
        byte[] signature = sign_payload(encrypted.getBytes(StandardCharsets.UTF_8));
        return encrypted + "|" + Base64.getEncoder().encodeToString(signature);
    }

    private String encrypt_aes_gcm(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        byte[] out = cipher.doFinal(data);
        int tagLen = 16;
        int ctLen = out.length - tagLen;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[tagLen];
        System.arraycopy(out, 0, ct, 0, ctLen);
        System.arraycopy(out, ctLen, tag, 0, tagLen);
        return Base64.getEncoder().encodeToString(iv) + "|" +
                Base64.getEncoder().encodeToString(ct) + "|" +
                Base64.getEncoder().encodeToString(tag);
    }

    private byte[] decrypt_aes_gcm(byte[] payload, byte[] key) throws Exception {
        String raw = new String(payload, StandardCharsets.UTF_8);
        String[] parts = raw.split("\\|", 3);
        if (parts.length != 3) {
            throw new IllegalArgumentException("invalid aes payload");
        }
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] ct = Base64.getDecoder().decode(parts[1]);
        byte[] tag = Base64.getDecoder().decode(parts[2]);
        byte[] combined = new byte[ct.length + tag.length];
        System.arraycopy(ct, 0, combined, 0, ct.length);
        System.arraycopy(tag, 0, combined, ct.length, tag.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        return cipher.doFinal(combined);
    }

    private String currentVersionString() {
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("dd.MM.yyyy - HH.mm");
        return LocalDateTime.now().format(fmt);
    }

    private int compareVersionDate(String a, String b) {
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("dd.MM.yyyy - HH.mm");
        try {
            LocalDateTime da = LocalDateTime.parse(a, fmt);
            LocalDateTime db = LocalDateTime.parse(b, fmt);
            return da.compareTo(db);
        } catch (Exception ex) {
            return a.compareTo(b);
        }
    }

    private String escape_json(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String rsa_encrypt(String jsonPayload, String name) throws Exception {
        if (jsonPayload == null || jsonPayload.isBlank()) {
            throw new IllegalArgumentException("missing json payload");
        }
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("missing name");
        }

        Optional<Kisi> kisi = kisiRepository.findByAd(name);
        if (kisi.isEmpty()) {
            throw new IllegalStateException("user not found");
        }

        String publicKeyBase64 = kisi.get().getPublicKey();
        if (publicKeyBase64 == null || publicKeyBase64.isBlank()) {
            throw new IllegalStateException("missing public key");
        }

        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64.replaceAll("\\s+", ""));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(spec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(jsonPayload.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String rsa_decrypt(String input) throws Exception {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("missing payload");
        }
        if (rsaPrivateKeyBase64 == null || rsaPrivateKeyBase64.isBlank()) {
            throw new IllegalStateException("missing private key");
        }
        log.warn("RSA decrypt debug: incoming base64 length={}", input.length());
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(rsaPrivateKeyBase64.replaceAll("\\s+", ""));
        } catch (Exception ex) {
            log.warn("RSA decrypt debug: private key base64 decode failed: {}", ex.toString());
            throw ex;
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (Exception ex) {
            log.warn("RSA decrypt debug: KeyFactory.getInstance failed: {}", ex.toString());
            throw ex;
        }
        PrivateKey privateKey;
        try {
            privateKey = kf.generatePrivate(spec);
        } catch (Exception ex) {
            log.warn("RSA decrypt debug: generatePrivate failed: {}", ex.toString());
            // Try PKCS#1 -> PKCS#8 wrap
            try {
                byte[] pkcs8 = wrapPkcs1ToPkcs8(keyBytes);
                privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            } catch (Exception ex2) {
                log.warn("RSA decrypt debug: PKCS#1 wrap failed: {}", ex2.toString());
                throw ex;
            }
        }
        log.warn("RSA private key class: {}", privateKey.getClass().getName());

        try {
            java.security.interfaces.RSAPrivateCrtKey rsa = (java.security.interfaces.RSAPrivateCrtKey) privateKey;
            java.security.spec.RSAPublicKeySpec pubSpec = new java.security.spec.RSAPublicKeySpec(
                    rsa.getModulus(), rsa.getPublicExponent());
            PublicKey pub = kf.generatePublic(pubSpec);
            String pubB64 = Base64.getEncoder().encodeToString(pub.getEncoded());
            log.warn("RSA public key len={}, modulusBits={}", pubB64.length(), rsa.getModulus().bitLength());
            log.warn("RSA public key (SPKI, base64): {}", pubB64);
        } catch (Exception ex) {
            log.warn("RSA public key derive failed: {}", ex.toString());
        }

        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        } catch (Exception ex) {
            log.warn("RSA decrypt debug: Cipher.getInstance failed: {}", ex.toString());
            throw ex;
        }
        try {
            OAEPParameterSpec oaep = new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaep);
        } catch (Exception ex) {
            log.warn("RSA decrypt debug: cipher.init failed: {}", ex.toString());
            throw ex;
        }
        byte[] encrypted;
        try {
            encrypted = Base64.getDecoder().decode(input);
            log.warn("RSA decrypt debug: encrypted bytes len={}", encrypted.length);
        } catch (Exception ex) {
            log.warn("RSA decrypt debug: payload base64 decode failed: {}", ex.toString());
            throw ex;
        }
        byte[] plain;
        try {
            plain = cipher.doFinal(encrypted);
        } catch (Exception ex) {
            log.warn("RSA decrypt debug: cipher.doFinal failed: {}", ex.toString());
            throw ex;
        }
        return new String(plain, StandardCharsets.UTF_8);
    }

    private byte[] wrapPkcs1ToPkcs8(byte[] pkcs1) {
        // PrivateKeyInfo ::= SEQUENCE {
        //   version INTEGER 0,
        //   algorithm AlgorithmIdentifier (rsaEncryption OID + NULL),
        //   privateKey OCTET STRING (PKCS#1 bytes)
        // }
        byte[] algId = new byte[] {
                0x30, 0x0D,
                0x06, 0x09, 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x01,
                0x05, 0x00
        };
        byte[] version = new byte[] { 0x02, 0x01, 0x00 };

        byte[] pkcs1Octet = concat(new byte[] { 0x04 }, encodeLength(pkcs1.length), pkcs1);
        byte[] seqBody = concat(version, algId, pkcs1Octet);
        return concat(new byte[] { 0x30 }, encodeLength(seqBody.length), seqBody);
    }

    private byte[] encodeLength(int len) {
        if (len < 0x80) {
            return new byte[] { (byte) len };
        }
        if (len <= 0xFF) {
            return new byte[] { (byte) 0x81, (byte) len };
        }
        return new byte[] { (byte) 0x82, (byte) (len >> 8), (byte) (len & 0xFF) };
    }

    private byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    private byte[] sign_payload(byte[] payload) throws Exception {
        if (payload == null || payload.length == 0) {
            throw new IllegalArgumentException("missing payload");
        }
        if (hmacKey == null || hmacKey.isBlank()) {
            throw new IllegalStateException("missing hmac key");
        }
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return mac.doFinal(payload);
    }

    private boolean verify_signature(byte[] payload, byte[] signature) throws Exception {
        if (payload == null || payload.length == 0) {
            throw new IllegalArgumentException("missing payload");
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("missing signature");
        }
        if (hmacKey == null || hmacKey.isBlank()) {
            throw new IllegalStateException("missing hmac key");
        }
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] expected = mac.doFinal(payload);
        return java.security.MessageDigest.isEqual(expected, signature);
    }

    private byte[] generate_aes_key() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private boolean canPublicPull(int yetki) {
        return switch (yetki) {
            case 0, 1, 2, 6, 7, 8, 9, 10, 11, 12, 13, 14 -> true;
            default -> false;
        };
    }

    private boolean canPublicPush(int yetki) {
        return switch (yetki) {
            case 1, 2, 6, 7, 9, 12, 13, 14 -> true;
            default -> false;
        };
    }

    private boolean canPublicManage(int yetki) {
        return switch (yetki) {
            case 2, 6, 7, 14 -> true;
            default -> false;
        };
    }

    private boolean canPrivatePull(int yetki) {
        return switch (yetki) {
            case 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 -> true;
            default -> false;
        };
    }

    private boolean canPrivatePush(int yetki) {
        return switch (yetki) {
            case 4, 5, 7, 8, 9, 11, 13, 14 -> true;
            default -> false;
        };
    }

    private boolean canPrivateManage(int yetki) {
        return switch (yetki) {
            case 5, 8, 9, 14 -> true;
            default -> false;
        };
    }

    private static final class RequestPayload {
        public String request;
        public String name;
        public String password;
        public String data;
    }

    private static final class PullState {
        private final String filePath;
        private final byte[] aesKey;

        private PullState(String filePath, byte[] aesKey) {
            this.filePath = filePath;
            this.aesKey = aesKey;
        }
    }

    private static final class PushState {
        private final String scope;
        private final String klasor;
        private final byte[] aesKey;
        private final String uploader;

        private PushState(String scope, String klasor, byte[] aesKey, String uploader) {
            this.scope = scope;
            this.klasor = klasor;
            this.aesKey = aesKey;
            this.uploader = uploader;
        }
    }
}
