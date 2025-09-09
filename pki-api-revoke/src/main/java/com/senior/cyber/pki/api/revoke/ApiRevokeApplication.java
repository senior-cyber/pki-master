package com.senior.cyber.pki.api.revoke;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.security.Security;

@SpringBootApplication(
        exclude = {LiquibaseAutoConfiguration.class},
        scanBasePackages = {"com.senior.cyber.pki.dao.repository", "com.senior.cyber.pki.api.revoke"}
)
@EnableJpaRepositories(basePackages = {"com.senior.cyber.pki.dao.repository"})
@EntityScan("com.senior.cyber.pki.dao.entity")
public class ApiRevokeApplication {

    static {
        if (Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(ApiRevokeApplication.class, args);
    }

    @Bean
    public PasswordEncryptor createPasswordEncryptor() {
        return new StrongPasswordEncryptor();
    }

}
