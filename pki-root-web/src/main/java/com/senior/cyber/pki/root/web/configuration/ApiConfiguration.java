package com.senior.cyber.pki.root.web.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "api", ignoreUnknownFields = true)
public class ApiConfiguration {

    private String aia;

    private String crl;

    public String getAia() {
        return aia;
    }

    public void setAia(String aia) {
        this.aia = aia;
    }

    public String getCrl() {
        return crl;
    }

    public void setCrl(String crl) {
        this.crl = crl;
    }

}
