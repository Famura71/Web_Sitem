package Transfer.Hibernate;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface KisiRepository extends JpaRepository<Kisi, Long> {
    Optional<Kisi> findByAdAndSifre(String ad, String sifre);
    Optional<Kisi> findByAd(String ad);
}
