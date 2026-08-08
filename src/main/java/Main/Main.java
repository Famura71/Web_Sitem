package Main;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = {"Main", "Server", "Database", "Transfer", "Fafnir"})
@EntityScan(basePackages = {"Transfer.Hibernate", "Server.Kahvehane"})
@EnableJpaRepositories(basePackages = {"Transfer.Hibernate", "Server.Kahvehane"})
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
}
