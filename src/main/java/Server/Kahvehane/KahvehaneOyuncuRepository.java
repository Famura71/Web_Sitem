package Server.Kahvehane;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface KahvehaneOyuncuRepository extends JpaRepository<KahvehaneOyuncu, Long> {
    Optional<KahvehaneOyuncu> findByKullaniciAdi(String kullaniciAdi);
    Optional<KahvehaneOyuncu> findByKullaniciAdiAndSifre(String kullaniciAdi, String sifre);
    List<KahvehaneOyuncu> findByIsBot(Boolean isBot);
    List<KahvehaneOyuncu> findTop10ByOrderByBakiyeDesc();
}
