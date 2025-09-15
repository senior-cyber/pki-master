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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
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
    public void run(String... args) throws IOException, InterruptedException, ApduException, ApplicationNotAvailableException, BadResponseException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String api = System.getProperty("api");
        String function = System.getProperty("function");

        String _format = System.getProperty("format");
        String _size = System.getProperty("size");
        String serialNumber = System.getProperty("serialNumber");
        String _slot = System.getProperty("slot");
        String managementKey = System.getProperty("managementKey");
        String pin = System.getProperty("pin");
        String _key = System.getProperty("key");

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
                KeyBcClientRegisterRequest request = new KeyBcClientRegisterRequest();
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
                KeyGenerateResponse response = KeyUtils.bcServerGenerate(new KeyBcGenerateRequest(size, format));
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
                    if (!keyInfo.isDecentralized()) {
                        // server remote api
                    } else {
                        // sign at client
                    }
                } else if (keyInfo.getType() == KeyTypeEnum.Yubico) {
                    KeyDownloadResponse keyDownload = KeyUtils.download(new KeyDownloadRequest(key.getKeyId(), key.getKeyPassword()));
                    YubicoPassword yubicoPassword = MAPPER.readValue(keyDownload.getPrivateKey(), YubicoPassword.class);
                    YubicoInfoResponse yubicoInfoResponse = KeyUtils.yubicoInfo();
                    // if it is local key or server key
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
            } else if ("root-client-generate".equals(function)) {
//                String subjectFile = System.getProperty("subject");
//                String publicKeyFile = System.getProperty("public-key");
//                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
//                Subject subject = MAPPER.readValue(subjectText, Subject.class);
//                X500Name _subject = SubjectUtils.generate(subject.getCountry(),
//                        subject.getOrganization(),
//                        subject.getOrganizationalUnit(),
//                        subject.getCommonName(),
//                        subject.getLocality(),
//                        subject.getProvince(),
//                        subject.getEmailAddress());
//
//                PublicKey publicKey = PublicKeyUtils.convert(publicKeyFile);
//
//                JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
//                LocalDate now = LocalDate.now();
//                Date notBefore = now.toDate();
//                Date notAfter = now.plusYears(10).toDate();
//                JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(_subject, BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, _subject, publicKey);
//                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
//                builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKey));
//                builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(publicKey));
//                builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign));
//
//                //        int shaSize = 256;
//                //        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
//                //        contentSignerBuilder.setProvider(issuerProvider);
//                //        ContentSigner contentSigner = contentSignerBuilder.build(issuerPrivateKey);
//                //
//                //        X509CertificateHolder holder = builder.build(contentSigner);
//                //        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
//                //        certificateConverter.setProvider(X509_PROVIDER);
//                //        return certificateConverter.getCertificate(holder);
//                X509Certificate rootCertificate = PkiUtils.issueRootCa(root.getProvider(), root.getPrivateKey(), root.getPublicKey(), rootSubject, now.toDate(), now.plusYears(10).toDate(), System.currentTimeMillis());
//                root.setCertificate(rootCertificate);
//                Certificate _rootCertificate = new Certificate();
//                _rootCertificate.setCountryCode(request.getCountry());
//                _rootCertificate.setOrganization(request.getOrganization());
//                _rootCertificate.setOrganizationalUnit(request.getOrganizationalUnit());
//                _rootCertificate.setCommonName(request.getCommonName());
//                _rootCertificate.setLocalityName(request.getLocality());
//                _rootCertificate.setStateOrProvinceName(request.getProvince());
//                _rootCertificate.setEmailAddress(request.getEmailAddress());
//                _rootCertificate.setKey(rootKey);
//                _rootCertificate.setCertificate(rootCertificate);
//                _rootCertificate.setSerial(rootCertificate.getSerialNumber().longValueExact());
//                _rootCertificate.setCreatedDatetime(new Date());
//                _rootCertificate.setValidFrom(rootCertificate.getNotBefore());
//                _rootCertificate.setValidUntil(rootCertificate.getNotAfter());
//                _rootCertificate.setStatus(CertificateStatusEnum.Good);
//                _rootCertificate.setType(CertificateTypeEnum.ROOT_CA);
//                this.certificateRepository.save(_rootCertificate);
//
//                // crl
//                Key crlKey = null;
//                {
//                    KeyPair x509 = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA);
//                    Key key = new Key();
//                    key.setStatus(KeyStatusEnum.Good);
//                    key.setType(KeyTypeEnum.BC);
//                    key.setKeySize(2048);
//                    key.setKeyFormat(KeyFormatEnum.RSA);
//                    key.setPrivateKey(PrivateKeyUtils.convert(x509.getPrivate()));
//                    key.setPublicKey(x509.getPublic());
//                    key.setCreatedDatetime(new Date());
//                    this.keyRepository.save(key);
//                    crlKey = key;
//                }
//                X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(root.getProvider(), root.getPrivateKey(), root.getCertificate(), crlKey.getPublicKey(), rootSubject, now.toDate(), now.plusYears(1).toDate(), _rootCertificate.getSerial() + 1);
//                Certificate crl = new Certificate();
//                crl.setIssuerCertificate(_rootCertificate);
//                crl.setCountryCode(request.getCountry());
//                crl.setOrganization(request.getOrganization());
//                crl.setOrganizationalUnit(request.getOrganizationalUnit());
//                crl.setCommonName(request.getCommonName());
//                crl.setLocalityName(request.getLocality());
//                crl.setStateOrProvinceName(request.getProvince());
//                crl.setEmailAddress(request.getEmailAddress());
//                crl.setKey(crlKey);
//                crl.setCertificate(crlCertificate);
//                crl.setSerial(crlCertificate.getSerialNumber().longValueExact());
//                crl.setCreatedDatetime(new Date());
//                crl.setValidFrom(crlCertificate.getNotBefore());
//                crl.setValidUntil(crlCertificate.getNotAfter());
//                crl.setStatus(CertificateStatusEnum.Good);
//                crl.setType(CertificateTypeEnum.CRL);
//                this.certificateRepository.save(crl);
//
//                // ocsp
//                Key ocspKey = null;
//                {
//                    KeyPair x509 = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA);
//                    Key key = new Key();
//                    key.setStatus(KeyStatusEnum.Good);
//                    key.setType(KeyTypeEnum.BC);
//                    key.setKeySize(2048);
//                    key.setKeyFormat(KeyFormatEnum.RSA);
//                    key.setPrivateKey(PrivateKeyUtils.convert(x509.getPrivate()));
//                    key.setPublicKey(x509.getPublic());
//                    key.setCreatedDatetime(new Date());
//                    this.keyRepository.save(key);
//                    ocspKey = key;
//                }
//                X500Name ocspSubject = SubjectUtils.generate(
//                        request.getCountry(),
//                        request.getOrganization(),
//                        request.getOrganizationalUnit(),
//                        request.getCommonName() + " OCSP",
//                        request.getLocality(),
//                        request.getProvince(),
//                        request.getEmailAddress()
//                );
//                X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(root.getProvider(), root.getPrivateKey(), root.getCertificate(), ocspKey.getPublicKey(), ocspSubject, now.toDate(), now.plusYears(1).toDate(), _rootCertificate.getSerial() + 2);
//                Certificate ocsp = new Certificate();
//                ocsp.setIssuerCertificate(_rootCertificate);
//                ocsp.setCountryCode(request.getCountry());
//                ocsp.setOrganization(request.getOrganization());
//                ocsp.setOrganizationalUnit(request.getOrganizationalUnit());
//                ocsp.setCommonName(request.getCommonName() + " OCSP");
//                ocsp.setLocalityName(request.getLocality());
//                ocsp.setStateOrProvinceName(request.getProvince());
//                ocsp.setEmailAddress(request.getEmailAddress());
//                ocsp.setKey(ocspKey);
//                ocsp.setCertificate(ocspCertificate);
//                ocsp.setSerial(ocspCertificate.getSerialNumber().longValueExact());
//                ocsp.setCreatedDatetime(new Date());
//                ocsp.setValidFrom(ocspCertificate.getNotBefore());
//                ocsp.setValidUntil(ocspCertificate.getNotAfter());
//                ocsp.setStatus(CertificateStatusEnum.Good);
//                ocsp.setType(CertificateTypeEnum.OCSP);
//                this.certificateRepository.save(ocsp);
//
//                _rootCertificate.setCrlCertificate(crl);
//                _rootCertificate.setOcspCertificate(_rootCertificate);
//                this.certificateRepository.save(_rootCertificate);
//
//                RootServerGenerateResponse response = new RootServerGenerateResponse();
//                response.setCertificateId(_rootCertificate.getId());
//                response.setKeyPassword(request.getKeyPassword());
//                response.setCertificate(rootCertificate);
//
//                PivSession session = sessions.get(serials.get(rootKey.getId()));
//                if (session != null) {
//                    Slot slot = slots.get(serials.get(rootKey.getId()));
//                    session.putCertificate(slot, rootCertificate);
//                }
            } else if ("root-client-register".equals(function)) {
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);
                RootResponse response = RootUtils.rootGenerate(new RootGenerateRequest(keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                if (response.getCertificate() != null) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
                }
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
