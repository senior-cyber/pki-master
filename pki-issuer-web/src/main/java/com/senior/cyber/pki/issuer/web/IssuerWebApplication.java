package com.senior.cyber.pki.issuer.web;

import com.google.crypto.tink.aead.AeadConfig;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.pki.issuer.web.utility.Crypto;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.jasypt.util.text.AES256TextEncryptor;
import org.jasypt.util.text.TextEncryptor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.security.Security;

@SpringBootApplication(
        exclude = {LiquibaseAutoConfiguration.class},
        scanBasePackages = {"com.senior.cyber.pki.service", "com.senior.cyber.pki.dao.repository", "com.senior.cyber.pki.issuer.web"}
)
@EnableJpaRepositories(basePackages = {"com.senior.cyber.pki.dao.repository"})
@EntityScan("com.senior.cyber.pki.dao.entity")
public class IssuerWebApplication {

    static {
        if (Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) throws Exception {
        AeadConfig.register();
        SpringApplication.run(IssuerWebApplication.class, args);
    }

    public static ApplicationContext getApplicationContext() {
        return WicketFactory.getApplicationContext();
    }

    @Bean
    public PasswordEncryptor createPasswordEncryptor() {
        return new StrongPasswordEncryptor();
    }

    @Bean
    public Crypto createCrypto() {
        return new Crypto();
    }

    @Bean
    public TextEncryptor createTextEncryptor() {
        AES256TextEncryptor encryptor = new AES256TextEncryptor();
        encryptor.setPassword(RandomStringUtils.randomAlphanumeric(50));
        return encryptor;
    }

}
