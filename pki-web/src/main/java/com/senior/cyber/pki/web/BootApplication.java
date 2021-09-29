package com.senior.cyber.pki.web;

import com.senior.cyber.pki.web.configuration.CryptoConfiguration;
import com.senior.cyber.pki.web.utility.Crypto;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.function.BootExtension;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.jasypt.util.text.AES256TextEncryptor;
import org.jasypt.util.text.TextEncryptor;
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
        BootExtension.run(BootApplication.class, args);
    }

    public static ApplicationContext getApplicationContext() {
        return WicketFactory.getApplicationContext();
    }

    @Bean
    public Gson createGson() {
        GsonBuilder builder = new GsonBuilder();
        builder.excludeFieldsWithoutExposeAnnotation();
        builder.setDateFormat("yyyy-MM-dd'T'HH:mm:ssZZ");
        return builder.create();
    }

    @Bean
    public PasswordEncryptor createPasswordEncryptor() {
        return new StrongPasswordEncryptor();
    }

    @Bean
    public Crypto createCrypto(CryptoConfiguration configuration) {
        return new Crypto(configuration.getIv());
    }

    @Bean
    public TextEncryptor createTextEncryptor() {
        AES256TextEncryptor encryptor = new AES256TextEncryptor();
        encryptor.setPassword(RandomStringUtils.randomAlphanumeric(50));
        return encryptor;
    }

}
