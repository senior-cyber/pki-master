package com.senior.cyber.pki.issuer.web;

import com.google.crypto.tink.aead.AeadConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.security.Security;

@SpringBootApplication(
        exclude = {LiquibaseAutoConfiguration.class},
        scanBasePackages = {"com.senior.cyber.pki.service", "com.senior.cyber.pki.dao.repository", "com.senior.cyber.pki.issuer.web"}
)
@EnableJpaRepositories(basePackages = {"com.senior.cyber.pki.dao.repository"})
@EntityScan("com.senior.cyber.pki.dao.entity")
public class IssuerWebApplication implements CommandLineRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(IssuerWebApplication.class);

    static {
        if (Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) throws Exception {
        AeadConfig.register();
        SpringApplication.run(IssuerWebApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        LOGGER.info("IssuerWebApplication started");
    }

}
