package com.senior.cyber.pki.root.web.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app", ignoreUnknownFields = true)
@Setter
@Getter
public class ApplicationConfiguration {

    private String secret;

    private Mode mode;

}
