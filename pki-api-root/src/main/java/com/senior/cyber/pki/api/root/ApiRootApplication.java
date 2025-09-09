package com.senior.cyber.pki.api.root;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.security.Security;

@SpringBootApplication(
        exclude = {LiquibaseAutoConfiguration.class},
        scanBasePackages = {"com.senior.cyber.pki.service", "com.senior.cyber.pki.dao.repository", "com.senior.cyber.pki.api.root"}
)
@EnableJpaRepositories(basePackages = {"com.senior.cyber.pki.dao.repository"})
@EntityScan("com.senior.cyber.pki.dao.entity")
public class ApiRootApplication {

    static {
        if (Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(ApiRootApplication.class, args);
    }

}
