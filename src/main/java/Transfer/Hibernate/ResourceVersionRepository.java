package Transfer.Hibernate;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ResourceVersionRepository extends JpaRepository<ResourceVersion, Long> {
    List<ResourceVersion> findAllByScopeIgnoreCaseAndKlasor(String scope, String klasor);
    List<ResourceVersion> findAllByScopeIgnoreCaseAndKlasorAndVersiyon(String scope, String klasor, String versiyon);
}
