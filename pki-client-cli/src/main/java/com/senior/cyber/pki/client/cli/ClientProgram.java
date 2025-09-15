package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.client.cli.dto.Key;
import com.senior.cyber.pki.client.cli.dto.Subject;
import com.senior.cyber.pki.client.cli.utils.IssuerUtils;
import com.senior.cyber.pki.client.cli.utils.KeyUtils;
import com.senior.cyber.pki.client.cli.utils.RevokeUtils;
import com.senior.cyber.pki.client.cli.utils.RootUtils;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.util.YubicoProviderUtils;
import com.senior.cyber.pki.common.x509.*;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.LocalDate;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@SpringBootApplication
public class ClientProgram implements CommandLineRunner {

    public static final Provider PROVIDER = new BouncyCastleProvider();

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
    public void run(String... args) throws IOException, InterruptedException, ApduException, ApplicationNotAvailableException, BadResponseException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, OperatorCreationException, CertificateException {
        String api = System.getProperty("api");
        String function = System.getProperty("function");

        String _format = System.getProperty("format");
        String _size = System.getProperty("size");
        String serialNumber = System.getProperty("serialNumber");
        String _slot = System.getProperty("slot");
        String managementKey = System.getProperty("managementKey");
        String pin = System.getProperty("pin");
        String _key = System.getProperty("key");
        String _subject = System.getProperty("subject");
        String _privateKey = System.getProperty("private-key");


        api = "key";
//        function = "bc-server-generate";
        function = "yubico-generate";
//        function = "download";

        api = "root";
        function = "root-generate";

        _key = "key.json";
        _format = "RSA";
        _size = "2048";
        serialNumber = "23275988";
        _slot = "9a";
        managementKey = MANAGEMENT_KEY;
        pin = PIN;

        if ("key".equals(api)) {
            if ("bc-client-generate".equals(function)) { // DONE
                KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
                int keySize = 0;
                switch (format) {
                    case EC -> {
                        keySize = 384;
                    }
                    case RSA -> {
                        keySize = 2048;
                    }
                }
                KeyPair keyPair = com.senior.cyber.pki.common.x509.KeyUtils.generate(format, keySize);
                BcRegisterRequest request = new BcRegisterRequest();
                request.setSize(keySize);
                request.setFormat(format);
                KeyBcClientRegisterResponse response = KeyUtils.bcClientRegister(request);
                if (response.getStatus() == 200) {
                    Signature signer = Signature.getInstance("SHA256withRSA", PROVIDER);
                    signer.initSign(keyPair.getPrivate());
                    signer.update(response.getKeyId().getBytes(StandardCharsets.UTF_8));
                    byte[] signatureBytes = signer.sign();
                    String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
                    Key key = new Key();
                    key.setKeyId(response.getKeyId());
                    key.setKeyPassword(signatureBase64);
                    System.out.println("wrote files");
                    FileUtils.write(new File("key.json"), MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key), StandardCharsets.UTF_8);
                    System.out.println("  " + "key.json");
                    FileUtils.write(new File("public-key.pem"), PublicKeyUtils.convert(keyPair.getPublic()), StandardCharsets.UTF_8);
                    System.out.println("  " + "public-key.pem");
                    FileUtils.write(new File("private-key.pem"), PrivateKeyUtils.convert(keyPair.getPrivate()), StandardCharsets.UTF_8);
                    System.out.println("  " + "private-key.pem");
                    FileUtils.write(new File("openssh-public-key.pub"), OpenSshPublicKeyUtils.convert(keyPair.getPublic()), StandardCharsets.UTF_8);
                    System.out.println("  " + "openssh-public-key.pub");
                    FileUtils.write(new File("openssh-private-key"), OpenSshPrivateKeyUtils.convert(keyPair.getPrivate()), StandardCharsets.UTF_8);
                    System.out.println("  " + "openssh-private-key");
                }
            } else if ("bc-server-generate".equals(function)) { // DONE
                int size = Integer.parseInt(_size);
                KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
                KeyGenerateResponse response = KeyUtils.bcServerGenerate(new BcGenerateRequest(size, format));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                Key key = new Key();
                key.setKeyId(response.getKeyId());
                key.setKeyPassword(response.getKeyPassword());
                System.out.println("wrote files");
                FileUtils.write(new File("key.json"), MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key), StandardCharsets.UTF_8);
                System.out.println("  " + "key.json");
            } else if ("yubico-generate".equals(function)) { // DONE
                YubicoInfoResponse infoResponse = KeyUtils.yubicoInfo();
                for (YubicoInfo info : infoResponse.getItems()) {
                    if (info.getSerialNumber().equals(serialNumber)) {
                        if ("client1".equals(info.getType())) {
                            int size = Integer.parseInt(_size);
                            if (managementKey == null || managementKey.isEmpty()) {
                                managementKey = MANAGEMENT_KEY;
                            }
                            Slot slot = null;
                            for (Slot __slot : Slot.values()) {
                                if (__slot.getStringAlias().equalsIgnoreCase(_slot)) {
                                    slot = __slot;
                                    break;
                                }
                            }
                            KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
                            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(serialNumber);
                            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                                PivSession session = new PivSession(connection);
                                session.authenticate(YubicoProviderUtils.hexStringToByteArray(managementKey));
                                PublicKey publicKey = null;
                                switch (format) {
                                    case RSA -> {
                                        switch (size) {
                                            case 1024 -> {
                                                publicKey = YubicoProviderUtils.generateKey(session, slot, KeyType.RSA1024);
                                            }
                                            case 2048 -> {
                                                publicKey = YubicoProviderUtils.generateKey(session, slot, KeyType.RSA2048);
                                            }
                                        }
                                    }
                                    case EC -> {
                                        switch (size) {
                                            case 256 -> {
                                                publicKey = YubicoProviderUtils.generateKey(session, slot, KeyType.ECCP256);
                                            }
                                            case 384 -> {
                                                publicKey = YubicoProviderUtils.generateKey(session, slot, KeyType.ECCP384);
                                            }
                                        }
                                    }
                                }
                                YubicoRegisterRequest request = new YubicoRegisterRequest(size, slot.getStringAlias(), serialNumber, managementKey, pin);
                                request.setFormat(format);
                                request.setPublicKey(publicKey);
                                KeyGenerateResponse response = KeyUtils.yubicoRegister(request);
                                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));

                                Key key = new Key();
                                key.setKeyId(response.getKeyId());
                                key.setKeyPassword(response.getKeyPassword());

                                System.out.println("wrote files");
                                FileUtils.write(new File("key.json"), MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key), StandardCharsets.UTF_8);
                                System.out.println("  " + "key.json");
                            }
                        } else if ("server".equals(info.getType())) {
                            int size = Integer.parseInt(_size);
                            KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
                            KeyGenerateResponse response = KeyUtils.yubicoGenerate(new YubicoGenerateRequest(size, format, serialNumber, _slot, managementKey));
                            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));

                            Key key = new Key();
                            key.setKeyId(response.getKeyId());
                            key.setKeyPassword(response.getKeyPassword());

                            System.out.println("wrote files");
                            FileUtils.write(new File("key.json"), MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key), StandardCharsets.UTF_8);
                            System.out.println("  " + "key.json");
                        }
                    }
                }
            } else if ("yubico-info".equals(function)) { // DONE
                YubicoInfoResponse response = KeyUtils.yubicoInfo();
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("info".equals(function)) { // DONE
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                KeyInfoRequest request = new KeyInfoRequest();
                request.setKeyId(key.getKeyId());
                request.setKeyPassword(key.getKeyPassword());
                KeyInfoResponse response = KeyUtils.info(request);
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("download".equals(function)) { // TODO:
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                KeyDownloadResponse response = KeyUtils.download(new KeyDownloadRequest(key.getKeyId(), key.getKeyPassword()));
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
            if ("root-generate".equals(function)) {
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                KeyInfoResponse keyInfo = KeyUtils.info(new KeyInfoRequest(key.getKeyId(), key.getKeyPassword()));
                if (keyInfo.getType() == KeyTypeEnum.BC) {
                    if (keyInfo.isDecentralized()) {

                        Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(_subject), StandardCharsets.UTF_8), Subject.class);
                        X500Name rootSubject = SubjectUtils.generate(subject.getCountry(),
                                subject.getOrganization(),
                                subject.getOrganizationalUnit(),
                                subject.getCommonName(),
                                subject.getLocality(),
                                subject.getProvince(),
                                subject.getEmailAddress());

                        KeyDownloadResponse keyDownload = KeyUtils.download(new KeyDownloadRequest(key.getKeyId(), key.getKeyPassword()));
                        PublicKey rootPublicKey = keyDownload.getPublicKey();
                        PrivateKey rootPrivateKey = PrivateKeyUtils.convert(_privateKey);

                        LocalDate now = LocalDate.now();
                        Date notBefore = now.toDate();
                        Date notAfter = now.plusYears(10).toDate();

                        long rootSerial = System.currentTimeMillis();
                        X509Certificate rootCertificate = PkiUtils.issueRootCa(PROVIDER, rootPrivateKey, rootPublicKey, rootSubject, notBefore, notAfter, rootSerial);

                        KeyPair crlKey = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA, 2048);
                        PublicKey crlPublicKey = crlKey.getPublic();
                        PrivateKey crlPrivateKey = crlKey.getPrivate();
                        X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(PROVIDER, rootPrivateKey, rootCertificate, crlPublicKey, rootSubject, now.toDate(), now.plusYears(1).toDate(), rootSerial + 1);

                        X500Name ocspSubject = SubjectUtils.generate(
                                subject.getCountry(),
                                subject.getOrganization(),
                                subject.getOrganizationalUnit(),
                                subject.getCommonName() + " OCSP",
                                subject.getLocality(),
                                subject.getProvince(),
                                subject.getEmailAddress()
                        );
                        KeyPair ocspKey = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA, 2048);
                        PublicKey ocspPublicKey = ocspKey.getPublic();
                        PrivateKey ocspPrivateKey = ocspKey.getPrivate();
                        X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(PROVIDER, rootPrivateKey, rootCertificate, ocspPublicKey, ocspSubject, now.toDate(), now.plusYears(1).toDate(), rootSerial + 2);

                        RootRegisterRequest request = new RootRegisterRequest();
                        request.setKeyId(key.getKeyId());
                        request.setKeyPassword(key.getKeyPassword());

                        request.setRootCertificate(rootCertificate);

                        request.setCrlCertificate(crlCertificate);
                        request.setCrlKeySize(2048);
                        request.setCrlKeyFormat(KeyFormatEnum.RSA);
                        request.setCrlPrivateKey(crlPrivateKey);

                        request.setOcspCertificate(ocspCertificate);
                        request.setOcspKeySize(2048);
                        request.setOcspKeyFormat(KeyFormatEnum.RSA);
                        request.setOcspPrivateKey(ocspPrivateKey);

                        RootResponse response = RootUtils.rootRegister(request);
                        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                        if (response.getCertificate() != null) {
                            System.out.println("wrote files");
                            FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                            System.out.println("  " + response.getCertificateId() + "-certificate.pem");
                        }
                    } else {
                        Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(_subject), StandardCharsets.UTF_8), Subject.class);
                        RootResponse response = RootUtils.rootGenerate(new RootGenerateRequest(key.getKeyId(), key.getKeyPassword(), subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
                        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                        if (response.getCertificate() != null) {
                            System.out.println("wrote files");
                            FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                            System.out.println("  " + response.getCertificateId() + "-certificate.pem");
                        }
                    }
                } else if (keyInfo.getType() == KeyTypeEnum.Yubico) {
                    KeyDownloadResponse keyDownload = KeyUtils.download(new KeyDownloadRequest(key.getKeyId(), key.getKeyPassword()));
                    YubicoPassword yubicoPassword = MAPPER.readValue(keyDownload.getPrivateKey(), YubicoPassword.class);
                    YubicoInfoResponse yubicoInfoResponse = KeyUtils.yubicoInfo();
                    // if it is local key
                    // if it is server key

                }
//                String keyId = System.getProperty("keyId");
//                KeyInfoResponse info = KeyUtils.info(new KeyInfoRequest(keyId));
//                if (!info.isDecentralized()) {
//                    String keyPassword = System.getProperty("keyPassword");
//                    Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(System.getProperty("subject")), StandardCharsets.UTF_8), Subject.class);
//                    RootServerGenerateResponse response = RootUtils.rootGenerate(new RootServerGenerateRequest(keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
//                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
//                    if (response.getCertificate() != null) {
//                        System.out.println("wrote files");
//                        FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
//                        System.out.println("  " + response.getCertificateId() + "-certificate.pem");
//                    }
//                } else {
//
//                }
            } else if ("subordinate-generate".equals(function)) {
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
