package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.client.cli.dto.Subject;
import com.senior.cyber.pki.client.cli.utils.IssuerUtils;
import com.senior.cyber.pki.client.cli.utils.KeyUtils;
import com.senior.cyber.pki.client.cli.utils.RevokeUtils;
import com.senior.cyber.pki.client.cli.utils.RootUtils;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.*;
import org.apache.commons.io.FileUtils;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class ClientProgram implements CommandLineRunner {

    private static final String MANAGEMENT_KEY = "010203040506070801020304050607080102030405060708";
    private static final String PIN = "123456";
    private static final String PUK = "12345678"; // PIN_UNLOCK_KEY

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String SSH = "https://pki-api-ssh.khmer.name";
    private static final String X509 = "https://pki-api-x509.khmer.name";
//    private static final String SSH = "http://127.0.0.1:3004";
//    private static final String X509 = "http://127.0.0.1:3003";

    public static void main(String[] args) {
        SpringApplication.run(ClientProgram.class, args);
    }

    @Override
    public void run(String... args) throws IOException, InterruptedException {
        String api = System.getProperty("api");
        if ("key".equals(api)) {
            String function = System.getProperty("function");
            if ("jca-generate".equals(function)) {
                Integer size = Integer.parseInt(System.getProperty("size"));
                KeyFormat format = KeyFormat.valueOf(System.getProperty("format"));
                KeyGenerateResponse response = KeyUtils.jcaGenerate(new JcaKeyGenerateRequest(size, format));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("yubico-info".equals(function)) {
                YubicoInfoResponse response = KeyUtils.yubicoInfo();
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("info".equals(function)) {
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                KeyInfoResponse response = KeyUtils.info(new KeyInfoRequest(keyId, keyPassword));
                if (response.getStatus() == 200) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(keyId + "-public-key.pem"), PublicKeyUtils.convert(response.getPublicKey()), StandardCharsets.UTF_8);
                    System.out.println("  " + keyId + "-public-key.pem");
                    FileUtils.write(new File(keyId + "-openssh-public-key.pub"), OpenSshPublicKeyUtils.convert(response.getOpenSshPublicKey()), StandardCharsets.UTF_8);
                    System.out.println("  " + keyId + "-openssh-public-key.pub");
                    if ("ServerKeyYubico".equals(response.getType())) {
                        if (response.getPrivateKey() != null) {
                            FileUtils.write(new File(keyId + "-private-key.json"), response.getPrivateKey(), StandardCharsets.UTF_8);
                            System.out.println("  " + keyId + "-private-key.json");
                        }
                    } else if ("ServerKeyJCE".equals(response.getType())) {
                        if (response.getPrivateKey() != null) {
                            FileUtils.write(new File(keyId + "-private-key.pem"), response.getPrivateKey(), StandardCharsets.UTF_8);
                            System.out.println("  " + keyId + "-private-key.pem");
                        }
                        if (response.getOpenSshPrivateKey() != null) {
                            FileUtils.write(new File(keyId + "-openssh-private-key.pem"), response.getOpenSshPrivateKey(), StandardCharsets.UTF_8);
                            System.out.println("  " + keyId + "-openssh-private-key.pem");
                        }
                    }
                } else {
                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                }
            } else if ("yubico-generate".equals(function)) {
                Integer size = Integer.parseInt(System.getProperty("size"));
                String serialNumber = System.getProperty("serialNumber");
                String slot = System.getProperty("slot");
                String managementKey = System.getProperty("managementKey");
                KeyFormat format = KeyFormat.valueOf(System.getProperty("format"));
                KeyGenerateResponse response = KeyUtils.yubicoGenerate(new YubicoKeyGenerateRequest(size, format, serialNumber, slot, managementKey));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("yubico-register".equals(function)) {
                String serialNumber = System.getProperty("serialNumber");
                String slot = System.getProperty("slot");
                String pin = System.getProperty("pin");
                String managementKey = System.getProperty("managementKey");
                KeyGenerateResponse response = KeyUtils.yubicoRegister(new YubicoKeyRegisterRequest(slot, serialNumber, managementKey, pin));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else {
                throw new RuntimeException("invalid function");
            }
        } else if ("revoke".equals(api)) {
            String function = System.getProperty("function");
            if ("revoke-certificate".equals(function)) {
                String certificateId = System.getProperty("certificateId");
                String keyPassword = System.getProperty("keyPassword");
                RevokeCertificateResponse response = RevokeUtils.revokeCertificate(new RevokeCertificateRequest(certificateId, keyPassword));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("revoke-key".equals(function)) {
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                RevokeKeyResponse response = RevokeUtils.revokeKey(new RevokeKeyRequest(keyId, keyPassword));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else {
                throw new RuntimeException("invalid function");
            }
        } else if ("root".equals(api)) {
            String function = System.getProperty("function");
            if ("root-generate".equals(function)) {
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);
                RootGenerateResponse response = RootUtils.rootGenerate(new RootGenerateRequest(keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                if (response.getCertificate() != null) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
                }
            } else if ("-subordinate-generate".equals(function)) {
                String issuerCertificateId = System.getProperty("issuerCertificateId");
                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);
                SubordinateGenerateResponse response = RootUtils.subordinateGenerate(new SubordinateGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                if (response.getCertificate() != null) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
                }
            } else if ("issuer-generate".equals(function)) {
                String issuerCertificateId = System.getProperty("issuerCertificateId");
                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String locality = System.getProperty("l");
                String province = System.getProperty("st");
                String country = System.getProperty("c");
                String commonName = System.getProperty("cn");
                String organization = System.getProperty("o");
                String organizationalUnit = System.getProperty("ou");
                String emailAddress = System.getProperty("emailAddress");
                IssuerGenerateResponse response = RootUtils.issuerGenerate(new IssuerGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, locality, province, country, commonName, organization, organizationalUnit, emailAddress));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                if (response.getCertificate() != null) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
                }
            } else {
                throw new RuntimeException("invalid function");
            }
        } else if ("issuer".equals(api)) {
            String function = System.getProperty("function");
            if ("ssh-client-generate".equals(function)) {
                String issuerKeyId = System.getProperty("issuerKeyId");
                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String principal = System.getProperty("principal");
                String server = System.getProperty("server");
                String alias = System.getProperty("alias");
                String period = System.getProperty("period");

                SshClientGenerateRequest request = new SshClientGenerateRequest(new Issuer(null, issuerKeyId, issuerKeyPassword), keyId, keyPassword, principal, server, alias, period);
                SshClientGenerateResponse response = IssuerUtils.sshClientGenerate(request);
                if (response.getStatus() == 200) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(keyId + "-openssh-certificate.pub"), OpenSshCertificateUtils.convert(response.getOpenSshCertificate()), StandardCharsets.UTF_8);
                    System.out.println("  " + keyId + "-openssh-certificate.pub");
                    FileUtils.write(new File(keyId + "-openssh-public-key.pub"), OpenSshPublicKeyUtils.convert(response.getOpenSshPublicKey()), StandardCharsets.UTF_8);
                    System.out.println("  " + keyId + "-openssh-public-key.pub");
                    List<String> config = new ArrayList<>();
                    if (response.getOpenSshPrivateKey() != null) {
                        FileUtils.write(new File(keyId + "-openssh-private-key"), OpenSshPrivateKeyUtils.convert(response.getOpenSshPrivateKey()), StandardCharsets.UTF_8);
                        System.out.println("  " + keyId + "-openssh-private-key");
                        config.add("Host " + request.getAlias());
                        config.add("    HostName " + request.getServer());
                        config.add("    User " + request.getPrincipal());
                        config.add("    IdentityFile " + keyId + "-openssh-private-key");
                        config.add("    CertificateFile " + keyId + "-openssh-certificate.pub");
                    } else {
                        config.add("Host " + request.getAlias());
                        config.add("    HostName " + request.getServer());
                        config.add("    User " + request.getPrincipal());
                        config.add("    PKCS11Provider /usr/local/lib/libykcs11.so");
                        config.add("    IdentityFile " + keyId + "-openssh-public-key.pub");
                        config.add("    CertificateFile " + keyId + "-openssh-certificate.pub");
                    }
                    FileUtils.writeLines(new File(keyId + "-config"), StandardCharsets.UTF_8.name(), config);
                    System.out.println("  " + keyId + "-config");
                }
            } else if ("issuer-generate".equals(function)) {
                String issuerCertificateId = System.getProperty("issuerCertificateId");
                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);
                IssuerGenerateResponse response = IssuerUtils.issuerGenerate(new IssuerGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                if (response.getCertificate() != null) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
                }
            } else if ("mtls-generate".equals(function)) {
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);
                MtlsGenerateRequest request = new MtlsGenerateRequest(keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress());
                MtlsGenerateResponse response = IssuerUtils.mtlsGenerate(request);
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                if (response.getCertificate() != null) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
                }
            } else if ("mtls-client-generate".equals(function)) {
                String issuerCertificateId = System.getProperty("issuerCertificateId");
                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);
                MtlsClientGenerateRequest request = new MtlsClientGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress());
                MtlsClientGenerateResponse response = IssuerUtils.mtlsClientGenerate(request);
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                if (response.getStatus() == 200) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");

                    FileUtils.write(new File(response.getCertificateId() + "-private-key.pem"), PrivateKeyUtils.convert(response.getPrivateKey()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-private-key.pem");
                }
            } else if ("server-generate".equals(function)) {
                String issuerCertificateId = System.getProperty("issuerCertificateId");
                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);
                ServerGenerateRequest request = new ServerGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress(), subject.getSans());
                ServerGenerateResponse response = IssuerUtils.serverGenerate(request);
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                if (response.getStatus() == 200) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(response.getCertificateId() + "-cert.pem"), CertificateUtils.convert(response.getCert()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-cert.pem");
                    FileUtils.write(new File(response.getCertificateId() + "-chain.pem"), CertificateUtils.convert(response.getChain()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-chain.pem");
                    FileUtils.write(new File(response.getCertificateId() + "-fullchain.pem"), CertificateUtils.convert(response.getFullchain()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-fullchain.pem");
                    FileUtils.write(new File(response.getCertificateId() + "-privkey.pem"), PrivateKeyUtils.convert(response.getPrivkey()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-privkey.pem");
                }
            } else {
                throw new RuntimeException("invalid api");
            }
        } else {
            throw new RuntimeException("invalid api");
        }
        System.exit(0);
    }

}
