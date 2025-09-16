package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.client.cli.utils.KeyUtils;
import com.senior.cyber.pki.client.cli.utils.RevokeUtils;
import com.senior.cyber.pki.client.cli.utils.RootUtils;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.dto.Certificate;
import com.senior.cyber.pki.common.dto.Key;
import com.senior.cyber.pki.common.util.Crypto;
import com.senior.cyber.pki.common.util.PivUtils;
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
import com.yubico.yubikit.piv.jca.PivProvider;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.util.text.AES256TextEncryptor;
import org.joda.time.DateTime;
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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

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
        if (managementKey == null || managementKey.isEmpty()){
            managementKey = MANAGEMENT_KEY;
        }
        String pin = System.getProperty("pin");
        if (pin == null || pin.isEmpty()){
            pin = PIN;
        }
        String _key = System.getProperty("key");
        String _certificate = System.getProperty("certificate");
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
                BcRegisterRequest request = BcRegisterRequest.builder().build();
                request.setSize(keySize);
                request.setFormat(format);
                request.setPublicKey(keyPair.getPublic());
                KeyGenerateResponse response = KeyUtils.bcClientRegister(request);
                if (response.getStatus() == 200) {
                    Signature signer = Signature.getInstance("SHA256withRSA", PROVIDER);
                    signer.initSign(keyPair.getPrivate());
                    signer.update(response.getKeyId().getBytes(StandardCharsets.UTF_8));
                    byte[] signatureBytes = signer.sign();
                    String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
                    Key key = Key.builder().build();
                    key.setKeyId(response.getKeyId());
                    key.setSize(keySize);
                    key.setFormat(format);
                    key.setType(KeyTypeEnum.BC);
                    key.setDecentralized(true);
                    key.setKeyPassword(signatureBase64);
                    key.setPrivateKey(PrivateKeyUtils.convert(keyPair.getPrivate()));
                    key.setPublicKey(keyPair.getPublic());
                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key));
                }
            } else if ("bc-server-generate".equals(function)) { // DONE
                int size = Integer.parseInt(_size);
                KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
                KeyGenerateResponse response = KeyUtils.bcServerGenerate(BcGenerateRequest.builder().size(size).format(format).emailAddress(emailAddress).build());
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                Key key = Key.builder().build();
                key.setKeyId(response.getKeyId());
                key.setKeyPassword(response.getKeyPassword());
                key.setPublicKey(response.getOpenSshPublicKey());
                key.setSize(size);
                key.setFormat(format);
                key.setType(KeyTypeEnum.BC);
                key.setDecentralized(false);
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key));
            } else if ("yubico-generate".equals(function)) { // DONE
                YubicoInfoResponse infoResponse = KeyUtils.yubicoInfo();
                for (YubicoInfo info : infoResponse.getItems()) {
                    if (info.getSerialNumber().equals(serialNumber)) {
                        if ("client".equals(info.getType())) {
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
                                YubicoRegisterRequest request = YubicoRegisterRequest.builder()
                                        .size(size)
                                        .slot(slot.getStringAlias())
                                        .serialNumber(serialNumber)
                                        .managementKey(managementKey)
                                        .pin(pin)
                                        .build();
                                request.setFormat(format);
                                request.setPublicKey(publicKey);
                                KeyGenerateResponse response = KeyUtils.yubicoRegister(request);

                                YubicoPassword yubico = YubicoPassword.builder().build();
                                yubico.setSerial(serialNumber);
                                yubico.setPin(pin);
                                yubico.setPivSlot(slot.getStringAlias());
                                yubico.setManagementKey(managementKey);

                                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                                encryptor.setPassword(response.getKeyPassword());
                                Key key = Key.builder().build();
                                key.setKeyId(response.getKeyId());
                                key.setKeyPassword(response.getKeyPassword());
                                key.setPublicKey(publicKey);
                                key.setPrivateKey(encryptor.encrypt(MAPPER.writeValueAsString(yubico)));
                                key.setSize(size);
                                key.setFormat(format);
                                key.setType(KeyTypeEnum.Yubico);
                                key.setDecentralized(false);
                                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key));
                            }
                        } else if ("server".equals(info.getType())) {
                            int size = Integer.parseInt(_size);
                            KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
                            KeyGenerateResponse response = KeyUtils.yubicoGenerate(
                                    YubicoGenerateRequest.builder()
                                            .size(size)
                                            .format(format)
                                            .serialNumber(serialNumber)
                                            .slot(_slot)
                                            .managementKey(managementKey)
                                            .build());

                            Key key = Key.builder().build();
                            key.setKeyId(response.getKeyId());
                            key.setKeyPassword(response.getKeyPassword());
                            key.setPublicKey(response.getOpenSshPublicKey());
                            key.setSize(size);
                            key.setFormat(format);
                            key.setType(KeyTypeEnum.Yubico);
                            key.setDecentralized(false);
                            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key));
                        }
                    }
                }
            } else if ("yubico-info".equals(function)) { // DONE
                YubicoInfoResponse response = KeyUtils.yubicoInfo();
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("info".equals(function)) { // DONE
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                KeyInfoRequest request = KeyInfoRequest.builder().build();
                request.setKeyId(key.getKeyId());
                KeyInfoResponse response = KeyUtils.info(request);
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("download".equals(function)) { // TODO:
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                KeyDownloadResponse response = KeyUtils.download(
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
                RevokeCertificateResponse response = RevokeUtils.revokeCertificate(RevokeCertificateRequest.builder().certificateId(certificateId).keyPassword(keyPassword).build());
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("revoke-key".equals(function)) {
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                RevokeKeyResponse response = RevokeUtils.revokeKey(RevokeKeyRequest.builder().keyId(keyId).keyPassword(keyPassword).build());
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else {
                throw new RuntimeException("invalid function");
            }
        } else if ("root".equals(api)) {
            if ("root-generate".equals(function)) { // DONE
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                if (key.getType() == KeyTypeEnum.BC) {
                    if (key.isDecentralized()) { // Client Sign
                        Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(_subject), StandardCharsets.UTF_8), Subject.class);
                        X500Name rootSubject = SubjectUtils.generate(subject.getCountry(),
                                subject.getOrganization(),
                                subject.getOrganizationalUnit(),
                                subject.getCommonName(),
                                subject.getLocality(),
                                subject.getProvince(),
                                subject.getEmailAddress());

                        PublicKey rootPublicKey = key.getPublicKey();
                        PrivateKey rootPrivateKey = PrivateKeyUtils.convert(key.getPrivateKey());
                        if (rootPrivateKey == null) {
                            throw new RuntimeException("root private key is not found");
                        }

                        LocalDate now = LocalDate.now();

                        long rootSerial = System.currentTimeMillis();
                        X509Certificate rootCertificate = PkiUtils.issueRootCa(PROVIDER, rootPrivateKey, rootPublicKey, rootSubject, now.toDate(), now.plusYears(10).toDate(), rootSerial);

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

                        RootRegisterRequest request = RootRegisterRequest.builder().build();
                        request.setKey(Key.builder()
                                .keyId(key.getKeyId())
                                .keyPassword(key.getKeyPassword())
                                .build());

                        request.setRootCertificate(rootCertificate);

                        request.setCrlCertificate(crlCertificate);
                        request.setCrlKeySize(2048);
                        request.setCrlKeyFormat(KeyFormatEnum.RSA);
                        request.setCrlPrivateKey(crlPrivateKey);

                        request.setOcspCertificate(ocspCertificate);
                        request.setOcspKeySize(2048);
                        request.setOcspKeyFormat(KeyFormatEnum.RSA);
                        request.setOcspPrivateKey(ocspPrivateKey);

                        RootRegisterResponse response = RootUtils.rootRegister(request);
                        if (response.getCertificate() != null) {
                            Certificate certificate = Certificate.builder().build();
                            certificate.setCertificateId(response.getCertificateId());
                            certificate.setKeyPassword(response.getKeyPassword());
                            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate));
                        }
                    } else { // Server Sign
                        Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(_subject), StandardCharsets.UTF_8), Subject.class);
                        RootGenerateResponse response = RootUtils.rootGenerate(RootGenerateRequest.builder()
                                .subject(subject)
                                .key(
                                        Key.builder()
                                                .keyId(key.getKeyId())
                                                .keyPassword(key.getKeyPassword())
                                                .build()
                                )
                                .build());
                        if (response.getCertificate() != null) {
                            Certificate certificate = Certificate.builder().build();
                            certificate.setCertificateId(response.getCertificateId());
                            certificate.setKeyPassword(response.getKeyPassword());
                            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate));
                        }
                    }
                } else if (key.getType() == KeyTypeEnum.Yubico) {
                    KeyDownloadResponse keyDownload = KeyUtils.download(KeyDownloadRequest.builder()
                            .keyId(key.getKeyId())
                            .keyPassword(key.getKeyPassword())
                            .build());
                    YubicoPassword yubico = MAPPER.readValue(keyDownload.getPrivateKey(), YubicoPassword.class);
                    YubicoInfoResponse yubicoInfoResponse = KeyUtils.yubicoInfo();
                    boolean found = false;
                    for (YubicoInfo item : yubicoInfoResponse.getItems()) {
                        if (item.getSerialNumber().equals(yubico.getSerial())) {
                            found = true;
                            if ("client".equals(item.getType())) { // Client Sign
                                Map<String, SmartCardConnection> connections = new HashMap<>();
                                Map<String, KeyStore> keys = new HashMap<>();
                                Map<String, PivProvider> providers = new HashMap<>();
                                Map<String, PivSession> sessions = new HashMap<>();
                                Map<String, Slot> slots = new HashMap<>();
                                Map<String, String> serials = new HashMap<>();

                                try {
                                    Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(_subject), StandardCharsets.UTF_8), Subject.class);
                                    X500Name rootSubject = SubjectUtils.generate(subject.getCountry(),
                                            subject.getOrganization(),
                                            subject.getOrganizationalUnit(),
                                            subject.getCommonName(),
                                            subject.getLocality(),
                                            subject.getProvince(),
                                            subject.getEmailAddress());

                                    PrivateKey rootPrivateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, key.getKeyId(), yubico);
                                    Crypto root = new Crypto(providers.get(serials.get(key.getKeyId())), keyDownload.getPublicKey(), rootPrivateKey);

                                    LocalDate now = LocalDate.now();

                                    long rootSerial = System.currentTimeMillis();
                                    X509Certificate rootCertificate = PkiUtils.issueRootCa(root.getProvider(), root.getPrivateKey(), root.getPublicKey(), rootSubject, now.toDate(), now.plusYears(10).toDate(), rootSerial);

                                    KeyPair crlKey = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA, 2048);
                                    PublicKey crlPublicKey = crlKey.getPublic();
                                    PrivateKey crlPrivateKey = crlKey.getPrivate();
                                    X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(root.getProvider(), root.getPrivateKey(), rootCertificate, crlPublicKey, rootSubject, now.toDate(), now.plusYears(1).toDate(), rootSerial + 1);

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
                                    X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(root.getProvider(), root.getPrivateKey(), rootCertificate, ocspPublicKey, ocspSubject, now.toDate(), now.plusYears(1).toDate(), rootSerial + 2);

                                    RootRegisterRequest request = RootRegisterRequest.builder().build();
                                    request.setKey(Key.builder()
                                            .keyId(key.getKeyId())
                                            .keyPassword(key.getKeyPassword())
                                            .build());

                                    request.setRootCertificate(rootCertificate);

                                    request.setCrlCertificate(crlCertificate);
                                    request.setCrlKeySize(2048);
                                    request.setCrlKeyFormat(KeyFormatEnum.RSA);
                                    request.setCrlPrivateKey(crlPrivateKey);

                                    request.setOcspCertificate(ocspCertificate);
                                    request.setOcspKeySize(2048);
                                    request.setOcspKeyFormat(KeyFormatEnum.RSA);
                                    request.setOcspPrivateKey(ocspPrivateKey);

                                    RootRegisterResponse response = RootUtils.rootRegister(request);
                                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                                    if (response.getCertificate() != null) {
                                        Certificate certificate = Certificate.builder().build();
                                        certificate.setCertificateId(response.getCertificateId());
                                        certificate.setKeyPassword(response.getKeyPassword());
                                        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate));
                                    }

                                    PivSession session = sessions.get(serials.get(key.getKeyId()));
                                    if (session != null) {
                                        Slot slot = slots.get(serials.get(key.getKeyId()));
                                        session.putCertificate(slot, rootCertificate);
                                    }
                                } finally {
                                    for (SmartCardConnection connection : connections.values()) {
                                        if (connection != null) {
                                            connection.close();
                                        }
                                    }
                                }
                            } else if ("server".equals(item.getType())) { // Server Sign
                                Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(_subject), StandardCharsets.UTF_8), Subject.class);
                                RootGenerateResponse response = RootUtils.rootGenerate(RootGenerateRequest.builder()
                                        .key(Key.builder()
                                                .keyId(key.getKeyId())
                                                .keyPassword(key.getKeyPassword())
                                                .build())
                                        .subject(subject).build());
                                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                                if (response.getCertificate() != null) {
                                    Certificate certificate = Certificate.builder().build();
                                    certificate.setCertificateId(response.getCertificateId());
                                    certificate.setKeyPassword(response.getKeyPassword());
                                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate));
                                }
                            }
                        }
                    }
                    if (!found) {
                        throw new RuntimeException("root private key is not found");
                    }
                }
            } else if ("subordinate-generate".equals(function)) {
                Certificate issuer = MAPPER.readValue(FileUtils.readFileToString(new File(_certificate), StandardCharsets.UTF_8), Certificate.class);
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                if (issuer.getType() == KeyTypeEnum.BC) {
                    if (issuer.isDecentralized()) {
                        if (issuer.getPrivateKey() != null && !issuer.getPrivateKey().isEmpty()) { // Client Sign

//                            if (rootPrivateKey == null) {
//                                throw new RuntimeException("root private key is not found");
//                            }
                            PrivateKey issuerPrivateKey = PrivateKeyUtils.convert(issuer.getPrivateKey());
                            DateTime now = DateTime.now();
                            Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(_subject), StandardCharsets.UTF_8), Subject.class);
                            ServerInfoResponse serverInfoResponse = RootUtils.serverInfo();
                            String hex = String.format("%012X", issuer.getCertificate().getSerialNumber().longValueExact());
                            long subordinateSerial = System.currentTimeMillis();

                            X500Name subordinateSubject = SubjectUtils.generate(
                                    subject.getCountry(),
                                    subject.getOrganization(),
                                    subject.getOrganizationalUnit(),
                                    subject.getCommonName(),
                                    subject.getLocality(),
                                    subject.getProvince(),
                                    subject.getEmailAddress()
                            );
                            PublicKey subordinatePublicKey = key.getPublicKey();
                            PrivateKey subordinatePrivateKey = PrivateKeyUtils.convert(issuer.getPrivateKey());
                            X509Certificate subordinateCertificate = PkiUtils.issueSubordinateCA(PROVIDER, issuerPrivateKey, issuer.getCertificate(),
                                    serverInfoResponse.getApiCrl() + "/" + hex + ".crl",
                                    serverInfoResponse.getApiOcsp() + "/" + hex,
                                    serverInfoResponse.getApiX509() + "/" + hex + ".der", null,
                                    subordinatePublicKey, subordinateSubject, now.toDate(), now.plusYears(5).toDate(), subordinateSerial);

                            KeyPair crlKey = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA, 2048);
                            PublicKey crlPublicKey = crlKey.getPublic();
                            PrivateKey crlPrivateKey = crlKey.getPrivate();
                            X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(PROVIDER, subordinatePrivateKey, subordinateCertificate, crlPublicKey, subordinateSubject, now.toDate(), now.plusYears(1).toDate(), subordinateSerial + 1);

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
                            X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(PROVIDER, subordinatePrivateKey, subordinateCertificate, ocspPublicKey, ocspSubject, now.toDate(), now.plusYears(1).toDate(), subordinateSerial + 2);

                            SubordinateRegisterRequest request = SubordinateRegisterRequest.builder().build();
                            request.setIssuer(Issuer.builder()
                                    .certificateId(issuer.getCertificateId())
                                    .keyPassword(issuer.getKeyPassword())
                                    .build());
                            request.setKey(
                                    Key.builder()
                                            .keyId(key.getKeyId())
                                            .keyPassword(key.getKeyPassword())
                                            .build());

                            request.setSubordinateCertificate(subordinateCertificate);

                            request.setCrlCertificate(crlCertificate);
                            request.setCrlKeySize(2048);
                            request.setCrlKeyFormat(KeyFormatEnum.RSA);
                            request.setCrlPrivateKey(crlPrivateKey);

                            request.setOcspCertificate(ocspCertificate);
                            request.setOcspKeySize(2048);
                            request.setOcspKeyFormat(KeyFormatEnum.RSA);
                            request.setOcspPrivateKey(ocspPrivateKey);

                            SubordinateRegisterResponse response = RootUtils.subordinateRegister(request);
                            if (response.getCertificate() != null) {
                                Certificate certificate = Certificate.builder().build();
                                certificate.setCertificateId(response.getCertificateId());
                                certificate.setKeyPassword(response.getKeyPassword());
                                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate));
                            }
                        } else { // Delegate to Server
                        }
                        // If has private key
                        // If has no private key, delegate to server
                        if (key.getType() == KeyTypeEnum.BC) {
                            // if have private key
                            // if have password key
                        }
                    } else {
                        // delegate to server
                    }
                }
//                else if (issuerInfo.getType() == KeyTypeEnum.Yubico) {
//                }

//                if (keyInfo.getType() == KeyTypeEnum.BC) {
//                    if (keyInfo.isDecentralized()) { // Client Sign
//                    } else { // Server Sign
//                    }
//                } else if (keyInfo.getType() == KeyTypeEnum.Yubico) { // Server Sign
//                    KeyDownloadResponse keyDownload = KeyUtils.download(new KeyDownloadRequest(key.getKeyId(), key.getKeyPassword()));
//                    YubicoPassword yubico = MAPPER.readValue(keyDownload.getPrivateKey(), YubicoPassword.class);
//                    YubicoInfoResponse yubicoInfoResponse = KeyUtils.yubicoInfo();
//                    for (YubicoInfo item : yubicoInfoResponse.getItems()) {
//                        if (item.getSerialNumber().equals(yubico.getSerial())) {
//                            if ("client".equals(item.getType())) { // Client Sign
//                            } else if ("server".equals(item.getType())) { // Client Sign
//                            }
//                        }
//                    }
//                }
//
//                String issuerCertificateId = System.getProperty("issuerCertificateId");
//                String issuerKeyPassword = System.getProperty("issuerKeyPassword");
//                String keyId = System.getProperty("keyId");
//                String keyPassword = System.getProperty("keyPassword");
//                String subjectFile = System.getProperty("subject");
//                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
//                Subject subject = MAPPER.readValue(subjectText, Subject.class);
//                SubordinateGenerateResponse response = RootUtils.subordinateGenerate(new SubordinateGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
//                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
//                if (response.getCertificate() != null) {
//                    System.out.println("wrote files");
//                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
//                }
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
//                IssuerGenerateResponse response = RootUtils.issuerGenerate(new IssuerGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, locality, province, country, commonName, organization, organizationalUnit, emailAddress));
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
