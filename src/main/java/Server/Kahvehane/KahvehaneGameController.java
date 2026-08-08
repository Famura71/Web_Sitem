package Server.Kahvehane;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/hermes")
public class KahvehaneGameController {

    private final KahvehaneOyuncuRepository repository;

    public KahvehaneGameController(KahvehaneOyuncuRepository repository) {
        this.repository = repository;
    }

    // Helper method to hash passwords using SHA-256
    private String hashPassword(String password) {
        if (password == null) return null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    @PostMapping("/auth/register")
    public ResponseEntity<ApiResponse> register(@RequestBody AuthRequest request) {
        if (request.username() == null || request.username().trim().isEmpty() ||
            request.password() == null || request.password().trim().isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Kullanıcı adı ve şifre boş olamaz!"));
        }

        String username = request.username().trim();
        if (repository.findByKullaniciAdi(username).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(new ApiResponse(false, "Bu kullanıcı adı zaten alınmış!"));
        }

        KahvehaneOyuncu oyuncu = new KahvehaneOyuncu(username, hashPassword(request.password()), 1000L, false);
        repository.save(oyuncu);

        return ResponseEntity.ok(new ApiResponse(true, "Kayıt başarılı! Giriş yapabilirsiniz."));
    }

    @PostMapping("/auth/login")
    public ResponseEntity<LoginResponse> login(@RequestBody AuthRequest request) {
        if (request.username() == null || request.password() == null) {
            return ResponseEntity.badRequest().body(new LoginResponse(false, "Kullanıcı adı ve şifre gönderilmelidir!", null));
        }

        String username = request.username().trim();
        String hashedPassword = hashPassword(request.password());

        Optional<KahvehaneOyuncu> oyuncuOpt = repository.findByKullaniciAdiAndSifre(username, hashedPassword);
        if (oyuncuOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new LoginResponse(false, "Hatalı kullanıcı adı veya şifre!", null));
        }

        KahvehaneOyuncu oyuncu = oyuncuOpt.get();
        if (oyuncu.getIsBot()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new LoginResponse(false, "Bot hesaplarıyla giriş yapılamaz!", null));
        }

        return ResponseEntity.ok(new LoginResponse(true, "Giriş başarılı!", new PlayerInfo(oyuncu)));
    }

    @GetMapping("/player/profile")
    public ResponseEntity<?> getProfile(@RequestParam String username) {
        Optional<KahvehaneOyuncu> oyuncuOpt = repository.findByKullaniciAdi(username);
        if (oyuncuOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse(false, "Oyuncu bulunamadı!"));
        }
        return ResponseEntity.ok(new PlayerInfo(oyuncuOpt.get()));
    }

    @PostMapping("/player/balance")
    public ResponseEntity<?> updateBalance(@RequestBody BalanceUpdateRequest request) {
        Optional<KahvehaneOyuncu> oyuncuOpt = repository.findByKullaniciAdi(request.username());
        if (oyuncuOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse(false, "Oyuncu bulunamadı!"));
        }

        KahvehaneOyuncu oyuncu = oyuncuOpt.get();
        oyuncu.setBakiye(Math.max(0L, oyuncu.getBakiye() + request.amountDiff()));

        if (request.gamePlayed() != null && request.gamePlayed()) {
            oyuncu.setGamesPlayed(oyuncu.getGamesPlayed() + 1);
            if (request.gameWon() != null && request.gameWon()) {
                oyuncu.setGamesWon(oyuncu.getGamesWon() + 1);
            }
        }

        repository.save(oyuncu);
        return ResponseEntity.ok(new PlayerInfo(oyuncu));
    }

    @GetMapping("/player/leaderboard")
    public ResponseEntity<List<PlayerInfo>> getLeaderboard() {
        List<KahvehaneOyuncu> players = repository.findTop10ByOrderByBakiyeDesc();
        List<PlayerInfo> leaderboard = players.stream().map(PlayerInfo::new).toList();
        return ResponseEntity.ok(leaderboard);
    }

    @PostMapping("/player/order")
    public ResponseEntity<OrderResponse> orderItem(@RequestBody OrderRequest request) {
        Optional<KahvehaneOyuncu> oyuncuOpt = repository.findByKullaniciAdi(request.username());
        if (oyuncuOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new OrderResponse(false, "Oyuncu bulunamadı!", null, 0L));
        }

        KahvehaneOyuncu oyuncu = oyuncuOpt.get();
        String item = request.orderType().toLowerCase();
        long cost = 0L;
        String message = "";

        switch (item) {
            case "cay" -> {
                cost = 10L; // 10 TL play money
                message = "Remzi Abi: Çayınız taze taze tavşan kanı geliyor yeğenim! Afiyet olsun.";
            }
            case "kahve" -> {
                cost = 30L; // 30 TL play money
                message = "Remzi Abi: Köpüklü orta Türk kahveni ocağa koydum. 40 yıl hatrımız olsun!";
            }
            case "tost" -> {
                cost = 50L; // 50 TL play money
                message = "Remzi Abi: Kaşarlı karışık tostun ızgarada cızırdayarak pişiyor. Sıcak sıcak ye!";
            }
            default -> {
                return ResponseEntity.badRequest().body(new OrderResponse(false, "Bilinmeyen sipariş!", null, oyuncu.getBakiye()));
            }
        }

        if (oyuncu.getBakiye() < cost) {
            return ResponseEntity.badRequest().body(new OrderResponse(false, "Bakiye yetersiz! Çay ocağı veresiye vermez.", null, oyuncu.getBakiye()));
        }

        oyuncu.setBakiye(oyuncu.getBakiye() - cost);
        repository.save(oyuncu);

        return ResponseEntity.ok(new OrderResponse(true, message, item, oyuncu.getBakiye()));
    }

    // DTO records
    public record AuthRequest(String username, String password) {}
    public record ApiResponse(boolean success, String message) {}
    public record LoginResponse(boolean success, String message, PlayerInfo player) {}
    public record BalanceUpdateRequest(String username, Long amountDiff, Boolean gamePlayed, Boolean gameWon) {}
    public record OrderRequest(String username, String orderType) {}
    public record OrderResponse(boolean success, String message, String item, long newBalance) {}

    public static class PlayerInfo {
        private final Long id;
        private final String kullaniciAdi;
        private final Long bakiye;
        private final Boolean isBot;
        private final Integer gamesPlayed;
        private final Integer gamesWon;

        public PlayerInfo(KahvehaneOyuncu oyuncu) {
            this.id = oyuncu.getId();
            this.kullaniciAdi = oyuncu.getKullaniciAdi();
            this.bakiye = oyuncu.getBakiye();
            this.isBot = oyuncu.getIsBot();
            this.gamesPlayed = oyuncu.getGamesPlayed();
            this.gamesWon = oyuncu.getGamesWon();
        }

        public Long getId() { return id; }
        public String getKullaniciAdi() { return kullaniciAdi; }
        public Long getBakiye() { return bakiye; }
        public Boolean getIsBot() { return isBot; }
        public Integer getGamesPlayed() { return gamesPlayed; }
        public Integer getGamesWon() { return gamesWon; }
    }
}
