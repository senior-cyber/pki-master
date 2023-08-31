package com.senior.cyber.pki.issuer.web.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.io.File;

@Configuration
@ConfigurationProperties(prefix = "server.ssl", ignoreUnknownFields = true)
@Setter
@Getter
public class SslConfiguration {

    private String keyStoreType;

    private File keyStore;

    private String keyStorePassword;

    private String keyAlias;

    private String keyPassword;

}
