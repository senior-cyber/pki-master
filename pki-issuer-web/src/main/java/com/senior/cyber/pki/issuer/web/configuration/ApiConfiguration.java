package com.senior.cyber.pki.issuer.web.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "api", ignoreUnknownFields = true)
@Setter
@Getter
public class ApiConfiguration {

    private String aia;

    private String crl;

}
