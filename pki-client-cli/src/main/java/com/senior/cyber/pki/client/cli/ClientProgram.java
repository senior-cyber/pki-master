package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.client.cli.utils.ClientUtils;
import com.senior.cyber.pki.client.cli.utils.KeyUtils;
import com.senior.cyber.pki.client.cli.utils.RootUtils;
import com.senior.cyber.pki.client.cli.utils.SubordinateUtils;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.dto.Key;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import com.senior.cyber.pki.common.x509.OpenSshPublicKeyUtils;
import com.senior.cyber.pki.common.x509.PublicKeyUtils;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;

@Slf4j
@SpringBootApplication
public class ClientProgram implements CommandLineRunner {

    public static final Provider PROVIDER = new BouncyCastleProvider();

    public static final String MANAGEMENT_KEY = "010203040506070801020304050607080102030405060708";
    public static final String PIN = "123456";
    public static final String PUK = "12345678"; // PIN_UNLOCK_KEY

    public static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String SSH = "https://pki-api-ssh.khmer.name";
    private static final String X509 = "https://pki-api-x509.khmer.name";
//    private static final String SSH = "http://127.0.0.1:3004";
//    private static final String X509 = "http://127.0.0.1:3003";

    public static void main(String[] args) {
        SpringApplication.run(ClientProgram.class, args);
    }

    @Override
    public void run(String... args) throws IOException, InterruptedException, ApduException, ApplicationNotAvailableException, BadResponseException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, OperatorCreationException, CertificateException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        String api = System.getProperty("api");
        String function = System.getProperty("function");

        String _format = System.getProperty("format");
        String _size = System.getProperty("size");
        String serialNumber = System.getProperty("serialNumber");
        String _slot = System.getProperty("slot");
        String managementKey = System.getProperty("managementKey");
        if (managementKey == null || managementKey.isEmpty()) {
            managementKey = MANAGEMENT_KEY;
        }
        String pin = System.getProperty("pin");
        if (pin == null || pin.isEmpty()) {
            pin = PIN;
        }
        String _key = System.getProperty("key");
        String _issuer = System.getProperty("issuer");
        String _subject = System.getProperty("subject");
        String emailAddress = System.getProperty("emailAddress");

//        api = "key";
//        function = "bc-client-generate";
//        function = "yubico-generate";
//        function = "download";

//        api = "root";
//        function = "root-generate";
//
//        _key = "key.json";
//        _certificate = "certificate.json";
//        _subject = "subject.json";
//        _format = "RSA";
//        _size = "2048";
//        serialNumber = "23275988";
//        _slot = "9a";
//        managementKey = MANAGEMENT_KEY;
//        pin = PIN;
//        emailAddress = "";

//        api = "key";
//        function = "bc-client-generate";
//        _format = "RSA";
//        emailAddress = "k.socheat@khmer.name";

        if ("key".equals(api)) {
            if ("bc-client-generate".equals(function)) { // DONE
                KeyUtils.bcClientGenerate(PROVIDER, _format, emailAddress);
            } else if ("bc-server-generate".equals(function)) { // DONE
                KeyUtils.bcServerGenerate(_size, _format, emailAddress);
            } else if ("yubico-generate".equals(function)) { // DONE
                YubicoInfoResponse infoResponse = ClientUtils.yubicoInfo();
                for (YubicoInfo info : infoResponse.getItems()) {
                    if (info.getSerialNumber().equals(serialNumber)) {
                        if ("client".equals(info.getType())) {
                            KeyUtils.yubicoClientGenerate(_slot, pin, _size, managementKey, _format, serialNumber, emailAddress, null);
                        } else if ("server".equals(info.getType())) {
                            KeyUtils.yubicoServerGenerate(_slot, managementKey, _size, _format, serialNumber, emailAddress);
                        }
                    }
                }
            } else if ("yubico-info".equals(function)) { // DONE
                YubicoInfoResponse response = ClientUtils.yubicoInfo();
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("info".equals(function)) { // DONE
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                KeyInfoRequest request = KeyInfoRequest.builder().build();
                request.setKeyId(key.getKeyId());
                KeyInfoResponse response = ClientUtils.info(request);
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("download".equals(function)) { // TODO:
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                KeyDownloadResponse response = ClientUtils.download(
                        KeyDownloadRequest.builder()
                                .keyId(key.getKeyId())
                                .keyPassword(key.getKeyPassword())
                                .build()
                );
                if (response.getStatus() == 200) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(key.getKeyId() + "-public-key.pem"), PublicKeyUtils.convert(response.getPublicKey()), StandardCharsets.UTF_8);
                    System.out.println("  " + key.getKeyId() + "-public-key.pem");
                    FileUtils.write(new File(key.getKeyId() + "-openssh-public-key.pub"), OpenSshPublicKeyUtils.convert(response.getOpenSshPublicKey()), StandardCharsets.UTF_8);
                    System.out.println("  " + key.getKeyId() + "-openssh-public-key.pub");
                    if (response.getType() == KeyTypeEnum.Yubico) {
                        if (response.getPrivateKey() != null) {
                            FileUtils.write(new File(key.getKeyId() + "-private-key.json"), response.getPrivateKey(), StandardCharsets.UTF_8);
                            System.out.println("  " + key.getKeyId() + "-private-key.json");
                        }
                    } else if (response.getType() == KeyTypeEnum.BC) {
                        if (response.getPrivateKey() != null) {
                            FileUtils.write(new File(key.getKeyId() + "-private-key.pem"), response.getPrivateKey(), StandardCharsets.UTF_8);
                            System.out.println("  " + key.getKeyId() + "-private-key.pem");
                        }
                        if (response.getOpenSshPrivateKey() != null) {
                            FileUtils.write(new File(key.getKeyId() + "-openssh-private-key.pem"), response.getOpenSshPrivateKey(), StandardCharsets.UTF_8);
                            System.out.println("  " + key.getKeyId() + "-openssh-private-key.pem");
                        }
                    }
                } else {
                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                }
            } else {
                throw new RuntimeException("invalid function");
            }
        } else if ("revoke".equals(api)) { // TODO:
            if ("revoke-certificate".equals(function)) {
                String certificateId = System.getProperty("certificateId");
                String keyPassword = System.getProperty("keyPassword");
                RevokeCertificateResponse response = ClientUtils.revokeCertificate(RevokeCertificateRequest.builder().certificateId(certificateId).keyPassword(keyPassword).build());
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("revoke-key".equals(function)) {
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                RevokeKeyResponse response = ClientUtils.revokeKey(RevokeKeyRequest.builder().keyId(keyId).keyPassword(keyPassword).build());
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else {
                throw new RuntimeException("invalid function");
            }
        } else if ("root".equals(api)) {
            if ("root-generate".equals(function)) { // DONE
                RootUtils.rootGenerate(_key, _subject);
            } else if ("subordinate-generate".equals(function)) {
                SubordinateUtils.subordinateGenerate(_issuer, _key, _subject, null);
            } else if ("issuer-generate".equals(function)) {
//                String issuerCertificateId = System.getProperty("issuerCertificateId");
//                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
//                String keyId = System.getProperty("keyId");
//                String keyPassword = System.getProperty("keyPassword");
//                String locality = System.getProperty("l");
//                String province = System.getProperty("st");
//                String country = System.getProperty("c");
//                String commonName = System.getProperty("cn");
//                String organization = System.getProperty("o");
//                String organizationalUnit = System.getProperty("ou");
//                IssuerGenerateResponse response = ClientUtils.issuerGenerate(new IssuerGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, locality, province, country, commonName, organization, organizationalUnit, emailAddress));
//                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
//                if (response.getCertificate() != null) {
//                    System.out.println("wrote files");
//                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
//                }
            } else {
                throw new RuntimeException("invalid function");
            }
        } else if ("issuer".equals(api)) {
            if ("ssh-client-generate".equals(function)) {
                String issuerKeyId = System.getProperty("issuerKeyId");
                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String principal = System.getProperty("principal");
                String server = System.getProperty("server");
                String alias = System.getProperty("alias");
                String period = System.getProperty("period");

//                SshClientGenerateRequest request = new SshClientGenerateRequest(new Issuer(null, issuerKeyId, issuerKeyPassword), keyId, keyPassword, principal, server, alias, period);
//                SshClientGenerateResponse response = IssuerUtils.sshClientGenerate(request);
//                if (response.getStatus() == 200) {
//                    System.out.println("wrote files");
//                    FileUtils.write(new File(keyId + "-openssh-certificate.pub"), OpenSshCertificateUtils.convert(response.getOpenSshCertificate()), StandardCharsets.UTF_8);
//                    System.out.println("  " + keyId + "-openssh-certificate.pub");
//                    FileUtils.write(new File(keyId + "-openssh-public-key.pub"), OpenSshPublicKeyUtils.convert(response.getOpenSshPublicKey()), StandardCharsets.UTF_8);
//                    System.out.println("  " + keyId + "-openssh-public-key.pub");
//                    List<String> config = new ArrayList<>();
//                    if (response.getOpenSshPrivateKey() != null) {
//                        FileUtils.write(new File(keyId + "-openssh-private-key"), OpenSshPrivateKeyUtils.convert(response.getOpenSshPrivateKey()), StandardCharsets.UTF_8);
//                        System.out.println("  " + keyId + "-openssh-private-key");
//                        config.add("Host " + request.getAlias());
//                        config.add("    HostName " + request.getServer());
//                        config.add("    User " + request.getPrincipal());
//                        config.add("    IdentityFile " + keyId + "-openssh-private-key");
//                        config.add("    CertificateFile " + keyId + "-openssh-certificate.pub");
//                    } else {
//                        config.add("Host " + request.getAlias());
//                        config.add("    HostName " + request.getServer());
//                        config.add("    User " + request.getPrincipal());
//                        config.add("    PKCS11Provider /usr/local/lib/libykcs11.so");
//                        config.add("    IdentityFile " + keyId + "-openssh-public-key.pub");
//                        config.add("    CertificateFile " + keyId + "-openssh-certificate.pub");
//                    }
//                    FileUtils.writeLines(new File(keyId + "-config"), StandardCharsets.UTF_8.name(), config);
//                    System.out.println("  " + keyId + "-config");
//                }
            } else if ("issuer-generate".equals(function)) {
//                String issuerCertificateId = System.getProperty("issuerCertificateId");
//                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
//                String keyId = System.getProperty("keyId");
//                String keyPassword = System.getProperty("keyPassword");
//                String subjectFile = System.getProperty("subject");
//                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
//                Subject subject = MAPPER.readValue(subjectText, Subject.class);
//                IssuerGenerateResponse response = IssuerUtils.issuerGenerate(new IssuerGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
//                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
//                if (response.getCertificate() != null) {
//                    System.out.println("wrote files");
//                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
//                }
            } else if ("mtls-generate".equals(function)) {
//                String keyId = System.getProperty("keyId");
//                String keyPassword = System.getProperty("keyPassword");
//                String subjectFile = System.getProperty("subject");
//                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
//                Subject subject = MAPPER.readValue(subjectText, Subject.class);
//                MtlsGenerateRequest request = new MtlsGenerateRequest(keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress());
//                MtlsGenerateResponse response = IssuerUtils.mtlsGenerate(request);
//                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
//                if (response.getCertificate() != null) {
//                    System.out.println("wrote files");
//                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
//                }
            } else if ("mtls-client-generate".equals(function)) {
//                String issuerCertificateId = System.getProperty("issuerCertificateId");
//                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
//                String keyId = System.getProperty("keyId");
//                String keyPassword = System.getProperty("keyPassword");
//                String subjectFile = System.getProperty("subject");
//                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
//                Subject subject = MAPPER.readValue(subjectText, Subject.class);
//                MtlsClientGenerateRequest request = new MtlsClientGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress());
//                MtlsClientGenerateResponse response = IssuerUtils.mtlsClientGenerate(request);
//                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
//                if (response.getStatus() == 200) {
//                    System.out.println("wrote files");
//                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
//
//                    FileUtils.write(new File(response.getCertificateId() + "-private-key.pem"), PrivateKeyUtils.convert(response.getPrivateKey()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-private-key.pem");
//                }
            } else if ("server-generate".equals(function)) {
//                String issuerCertificateId = System.getProperty("issuerCertificateId");
//                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
//                String keyId = System.getProperty("keyId");
//                String keyPassword = System.getProperty("keyPassword");
//                String subjectFile = System.getProperty("subject");
//                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
//                Subject subject = MAPPER.readValue(subjectText, Subject.class);
//                ServerGenerateRequest request = new ServerGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress(), subject.getSans());
//                ServerGenerateResponse response = IssuerUtils.serverGenerate(request);
//                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
//                if (response.getStatus() == 200) {
//                    System.out.println("wrote files");
//                    FileUtils.write(new File(response.getCertificateId() + "-cert.pem"), CertificateUtils.convert(response.getCert()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-cert.pem");
//                    FileUtils.write(new File(response.getCertificateId() + "-chain.pem"), CertificateUtils.convert(response.getChain()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-chain.pem");
//                    FileUtils.write(new File(response.getCertificateId() + "-fullchain.pem"), CertificateUtils.convert(response.getFullchain()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-fullchain.pem");
//                    FileUtils.write(new File(response.getCertificateId() + "-privkey.pem"), PrivateKeyUtils.convert(response.getPrivkey()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-privkey.pem");
//                }
            } else {
                throw new RuntimeException("invalid api");
            }
        } else {
            throw new RuntimeException("invalid api");
        }
        System.exit(0);
    }

}
