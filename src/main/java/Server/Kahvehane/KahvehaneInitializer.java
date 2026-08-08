package Server.Kahvehane;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class KahvehaneInitializer implements CommandLineRunner {

    private final KahvehaneOyuncuRepository repository;

    public KahvehaneInitializer(KahvehaneOyuncuRepository repository) {
        this.repository = repository;
    }

    @Override
    public void run(String... args) throws Exception {
        // Predefined list of authentic Turkish coffeehouse bots
        List<KahvehaneOyuncu> bots = List.of(
                new KahvehaneOyuncu("Nuri Dayı", "bot-no-pass", 5000L, true),
                new KahvehaneOyuncu("Ahmet Dayı", "bot-no-pass", 10000L, true),
                new KahvehaneOyuncu("Hüseyin Amca", "bot-no-pass", 2000L, true),
                new KahvehaneOyuncu("Cemil Abi", "bot-no-pass", 1500L, true),
                new KahvehaneOyuncu("Ocakçı Remzi", "bot-no-pass", 3000L, true)
        );

        for (KahvehaneOyuncu bot : bots) {
            if (repository.findByKullaniciAdi(bot.getKullaniciAdi()).isEmpty()) {
                repository.save(bot);
            }
        }
    }
}
