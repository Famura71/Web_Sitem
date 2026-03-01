package Transfer.Hibernate;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PublicResourceRepository extends JpaRepository<PublicResource, Long> {
    List<PublicResource> findAllByNameIn(Iterable<String> names);
    void deleteByNameIn(Iterable<String> names);
}
