package com.senior.cyber.pki.api.key;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@SpringBootApplication(
        exclude = {LiquibaseAutoConfiguration.class},
        scanBasePackages = {"com.senior.cyber.pki.service", "com.senior.cyber.pki.dao.repository", "com.senior.cyber.pki.api.key"}
)
@EnableJpaRepositories(basePackages = {"com.senior.cyber.pki.dao.repository"})
@EntityScan("com.senior.cyber.pki.dao.entity")
public class ApiKeyApplication implements CommandLineRunner {

    @Autowired
    private JavaMailSender mailSender;

    public static void main(String[] args) {
        SpringApplication.run(ApiKeyApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("");
        message.setTo("");
        message.setSubject("Key API Service");
        message.setText("Key API is ready to serve request");
        mailSender.send(message);
    }

}
