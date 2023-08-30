package com.senior.cyber.pki.client.cli;

import com.senior.cyber.pki.common.x509.CrlUtils;
import com.senior.cyber.pki.common.x509.OcspUtils;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.security.Security;
import java.util.List;
import java.util.Optional;

@SpringBootApplication(
        exclude = {LiquibaseAutoConfiguration.class},
        scanBasePackages = {"com.senior.cyber.pki.dao.repository", "com.senior.cyber.pki.client.cli"}
)
@EnableJpaRepositories(basePackages = {"com.senior.cyber.pki.dao.repository"})
@EntityScan("com.senior.cyber.pki.dao.entity")
public class ClientProgram {

    static {
        if (Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) throws Exception {
        ApplicationContext context = SpringApplication.run(ClientProgram.class, args);
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
        Optional<Certificate> optionalCertificate = certificateRepository.findBySerial(21L);
        Certificate certificate = optionalCertificate.orElse(null);

        Optional<Certificate> optionalRootCertificate = certificateRepository.findBySerial(1L);
        Certificate rootCertificate = optionalRootCertificate.orElse(null);

        List<String> crls = CrlUtils.lookupUrl(certificate.getCertificate());
        List<String> ocsps = OcspUtils.lookupUrl(certificate.getCertificate());

        System.out.println(CrlUtils.validate(certificate.getCertificate(), crls.get(0)));
        System.out.println(OcspUtils.validate(certificate.getCertificate(), rootCertificate.getCertificate(), ocsps.get(0)));
        System.exit(0);
    }

    @Bean
    public PasswordEncryptor createPasswordEncryptor() {
        return new StrongPasswordEncryptor();
    }

}
