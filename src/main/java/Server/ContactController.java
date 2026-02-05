package Server;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;

@RestController
public class ContactController {
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
            "zip", "rar", "7z",
            "png", "jpg", "jpeg", "webp",
            "mp3", "mp4"
    );

    private final JavaMailSender mailSender;

    @Value("${contact.recipient:furkanahmet.karabulut@outlook.com}")
    private String recipient;

    public ContactController(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @PostMapping(value = "/api/contact", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> submit(
            @RequestParam("isim") String name,
            @RequestParam("mesaj") String message,
            @RequestParam(value = "dosya", required = false) MultipartFile file
    ) {
        if (name == null || name.isBlank() || message == null || message.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Name and message are required.");
        }

        Path tempFile = null;
        try {
            AttachmentInfo attachmentInfo = null;
            if (file != null && !file.isEmpty()) {
                String originalName = file.getOriginalFilename() != null ? file.getOriginalFilename() : "attachment";
                String extension = getExtension(originalName);
                if (!ALLOWED_EXTENSIONS.contains(extension)) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Unsupported file type.");
                }
                tempFile = Files.createTempFile("contact-", "-" + originalName);
                file.transferTo(tempFile);
                ScanResult scan = scanWithClamAV(tempFile);
                if (scan.status == ScanStatus.CLEAN) {
                    attachmentInfo = new AttachmentInfo(originalName, tempFile);
                } else if (scan.status == ScanStatus.INFECTED) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("File failed virus scan.");
                } else {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Virus scan failed.");
                }
            }

            sendMail(name, message, attachmentInfo);
            return ResponseEntity.ok("Sent");
        } catch (IOException | MessagingException | InterruptedException ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to send.");
        } finally {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException ignored) {
                    // Best-effort cleanup.
                }
            }
        }
    }

    private void sendMail(String name, String message, AttachmentInfo attachmentInfo) throws MessagingException {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, attachmentInfo != null);
        helper.setTo(recipient);
        helper.setSubject("Yeni Iletisim Mesaji");
        helper.setText("Isim: " + name + "\n\nMesaj:\n" + message);
        if (attachmentInfo != null) {
            helper.addAttachment(attachmentInfo.originalName, attachmentInfo.path.toFile());
        }
        mailSender.send(mimeMessage);
    }

    private ScanResult scanWithClamAV(Path file) throws IOException, InterruptedException {
        Process process = new ProcessBuilder("clamscan", "--no-summary", file.toAbsolutePath().toString())
                .redirectErrorStream(true)
                .start();
        int exit = process.waitFor();
        if (exit == 0) {
            return new ScanResult(ScanStatus.CLEAN);
        }
        if (exit == 1) {
            return new ScanResult(ScanStatus.INFECTED);
        }
        return new ScanResult(ScanStatus.ERROR);
    }

    private String getExtension(String filename) {
        int idx = filename.lastIndexOf('.');
        if (idx < 0 || idx == filename.length() - 1) {
            return "";
        }
        return filename.substring(idx + 1).toLowerCase(Locale.ROOT);
    }

    private enum ScanStatus { CLEAN, INFECTED, ERROR }

    private record ScanResult(ScanStatus status) {}

    private record AttachmentInfo(String originalName, Path path) {}
}
