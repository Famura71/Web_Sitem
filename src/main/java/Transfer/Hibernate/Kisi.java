package Transfer.Hibernate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "kisiler")
public class Kisi {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ad", nullable = false)
    private String ad;

    @Column(name = "sifre", nullable = false)
    private String sifre;

    @Column(name = "yetki_seviyesi", nullable = false)
    private int yetkiSeviyesi;

    @Column(name = "public_key", columnDefinition = "LONGTEXT")
    private String publicKey;

    public Long getId() {
        return id;
    }

    public String getAd() {
        return ad;
    }

    public void setAd(String ad) {
        this.ad = ad;
    }

    public String getSifre() {
        return sifre;
    }

    public void setSifre(String sifre) {
        this.sifre = sifre;
    }

    public int getYetkiSeviyesi() {
        return yetkiSeviyesi;
    }

    public void setYetkiSeviyesi(int yetkiSeviyesi) {
        this.yetkiSeviyesi = yetkiSeviyesi;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
