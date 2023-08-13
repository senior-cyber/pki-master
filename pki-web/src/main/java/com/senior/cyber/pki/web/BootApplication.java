package com.senior.cyber.pki.web;

import com.google.crypto.tink.aead.AeadConfig;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.pki.web.utility.Crypto;
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
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;

import java.security.Security;

@SpringBootApplication(exclude = {LiquibaseAutoConfiguration.class})
@EntityScan("com.senior.cyber.pki.dao.entity")
@EnableJdbcHttpSession(tableName = "TBL_SESSION")
public class BootApplication {

    static {
        if (Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) throws Exception {
        AeadConfig.register();
        SpringApplication.run(BootApplication.class, args);
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
