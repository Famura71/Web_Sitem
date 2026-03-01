package Transfer.Hibernate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "resources_versions")
public class ResourceVersion {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "klasor", nullable = false)
    private String klasor;

    @Column(name = "isim", nullable = false)
    private String isim;

    @Column(name = "scope", nullable = false)
    private String scope;

    @Column(name = "versiyon", nullable = false, columnDefinition = "TEXT")
    private String versiyon;

    @Column(name = "yukleyen", nullable = false, columnDefinition = "TEXT")
    private String yukleyen;

    public ResourceVersion() {
    }

    public ResourceVersion(String klasor, String isim, String scope, String versiyon, String yukleyen) {
        this.klasor = klasor;
        this.isim = isim;
        this.scope = scope;
        this.versiyon = versiyon;
        this.yukleyen = yukleyen;
    }

    public Long getId() {
        return id;
    }

    public String getKlasor() {
        return klasor;
    }

    public void setKlasor(String klasor) {
        this.klasor = klasor;
    }

    public String getIsim() {
        return isim;
    }

    public void setIsim(String isim) {
        this.isim = isim;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getVersiyon() {
        return versiyon;
    }

    public void setVersiyon(String versiyon) {
        this.versiyon = versiyon;
    }

    public String getYukleyen() {
        return yukleyen;
    }

    public void setYukleyen(String yukleyen) {
        this.yukleyen = yukleyen;
    }
}
