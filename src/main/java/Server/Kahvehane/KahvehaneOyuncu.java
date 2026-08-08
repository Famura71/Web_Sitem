package Server.Kahvehane;

import jakarta.persistence.*;

@Entity
@Table(name = "kahvehane_oyuncular")
public class KahvehaneOyuncu {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "kullanici_adi", unique = true, nullable = false)
    private String kullaniciAdi;

    @Column(name = "sifre")
    private String sifre;

    @Column(name = "bakiye", nullable = false)
    private Long bakiye = 1000L;

    @Column(name = "is_bot", nullable = false)
    private Boolean isBot = false;

    @Column(name = "games_played", nullable = false)
    private Integer gamesPlayed = 0;

    @Column(name = "games_won", nullable = false)
    private Integer gamesWon = 0;

    public KahvehaneOyuncu() {
    }

    public KahvehaneOyuncu(String kullaniciAdi, String sifre, Long bakiye, Boolean isBot) {
        this.kullaniciAdi = kullaniciAdi;
        this.sifre = sifre;
        this.bakiye = bakiye;
        this.isBot = isBot;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getKullaniciAdi() {
        return kullaniciAdi;
    }

    public void setKullaniciAdi(String kullaniciAdi) {
        this.kullaniciAdi = kullaniciAdi;
    }

    public String getSifre() {
        return sifre;
    }

    public void setSifre(String sifre) {
        this.sifre = sifre;
    }

    public Long getBakiye() {
        return bakiye;
    }

    public void setBakiye(Long bakiye) {
        this.bakiye = bakiye;
    }

    public Boolean getIsBot() {
        return isBot;
    }

    public void setIsBot(Boolean bot) {
        isBot = bot;
    }

    public Integer getGamesPlayed() {
        return gamesPlayed;
    }

    public void setGamesPlayed(Integer gamesPlayed) {
        this.gamesPlayed = gamesPlayed;
    }

    public Integer getGamesWon() {
        return gamesWon;
    }

    public void setGamesWon(Integer gamesWon) {
        this.gamesWon = gamesWon;
    }
}
