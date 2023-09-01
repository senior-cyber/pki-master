package com.senior.cyber.pki.root.web.configuration;

import com.senior.cyber.pki.root.web.utility.Crypto;
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BeanConfiguration {

    @Bean
    public PasswordEncryptor createPasswordEncryptor() {
        return new StrongPasswordEncryptor();
    }

    @Bean
    public Crypto createCrypto() {
        return new Crypto();
    }

}
