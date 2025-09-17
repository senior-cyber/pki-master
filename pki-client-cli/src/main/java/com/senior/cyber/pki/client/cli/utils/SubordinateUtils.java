package com.senior.cyber.pki.client.cli.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.client.cli.ClientProgram;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.dto.Certificate;
import com.senior.cyber.pki.common.dto.Key;
import com.senior.cyber.pki.common.util.Crypto;
import com.senior.cyber.pki.common.util.PivUtils;
import com.senior.cyber.pki.common.x509.*;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.util.text.AES256TextEncryptor;
import org.joda.time.DateTime;
import org.joda.time.LocalDate;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class SubordinateUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void subordinateGenerate(String _issuer, String _key, String _subject, String output) throws IOException, InterruptedException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException, ApduException, SignatureException, InvalidKeyException, ApplicationNotAvailableException {
        Certificate issuer = MAPPER.readValue(FileUtils.readFileToString(new File(_issuer), StandardCharsets.UTF_8), Certificate.class);
        if (issuer.getType() == KeyTypeEnum.BC) {
            if (issuer.isDecentralized()) {
                Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
                if (issuer.getPrivateKey() != null && !issuer.getPrivateKey().isEmpty()) { // Client Sign

//                            if (rootPrivateKey == null) {
//                                throw new RuntimeException("root private key is not found");
//                            }
                    PrivateKey issuerPrivateKey = PrivateKeyUtils.convert(issuer.getPrivateKey());
                    DateTime now = DateTime.now();
                    Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(_subject), StandardCharsets.UTF_8), Subject.class);
                    ServerInfoResponse serverInfoResponse = ClientUtils.serverInfoV1();
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
                    X509Certificate subordinateCertificate = PkiUtils.issueSubordinateCA(ClientProgram.PROVIDER, issuerPrivateKey, issuer.getCertificate(),
                            serverInfoResponse.getApiCrl() + "/" + hex + ".crl",
                            serverInfoResponse.getApiOcsp() + "/" + hex,
                            serverInfoResponse.getApiX509() + "/" + hex + ".der", null,
                            subordinatePublicKey, subordinateSubject, now.toDate(), now.plusYears(5).toDate(), subordinateSerial);

                    KeyPair crlKey = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA, 2048);
                    PublicKey crlPublicKey = crlKey.getPublic();
                    PrivateKey crlPrivateKey = crlKey.getPrivate();
                    X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(ClientProgram.PROVIDER, subordinatePrivateKey, subordinateCertificate, crlPublicKey, subordinateSubject, now.toDate(), now.plusYears(1).toDate(), subordinateSerial + 1);

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
                    X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(ClientProgram.PROVIDER, subordinatePrivateKey, subordinateCertificate, ocspPublicKey, ocspSubject, now.toDate(), now.plusYears(1).toDate(), subordinateSerial + 2);

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

                    SubordinateRegisterResponse response = ClientUtils.subordinateRegister(request);
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
        } else if (issuer.getType() == KeyTypeEnum.Yubico) {
            Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
            if (key.getType() == KeyTypeEnum.Yubico) {
                YubicoInfoResponse yubicoInfoResponse = ClientUtils.yubicoInfo();
                if (yubicoInfoResponse.getItems() != null && !yubicoInfoResponse.getItems().isEmpty()) {
                    AES256TextEncryptor encryptor = new AES256TextEncryptor();
                    encryptor.setPassword(key.getKeyPassword());
                    YubicoPassword yubico = MAPPER.readValue(encryptor.decrypt(key.getPrivateKey()), YubicoPassword.class);
                    boolean found = false;
                    for (YubicoInfo item : yubicoInfoResponse.getItems()) {
                        if (item.getSerialNumber().equals(yubico.getSerial())) {
                            found = true;
                            if ("client".equals(item.getType())) { // Client Sign
                                subordinateGenerateYubicoClientSign(_key, _subject, null);
                            } else if ("server".equals(item.getType())) { // Server Sign
                                subordinateGenerateYubicoServerSign(_key, _subject, null);
                            }
                        }
                    }
                    if (!found) {
                        throw new RuntimeException("root private key is not found");
                    }
                }
            }
        }

//                if (keyInfo.getType() == KeyTypeEnum.BC) {
//                    if (keyInfo.isDecentralized()) { // Client Sign
//                    } else { // Server Sign
//                    }
//                } else if (keyInfo.getType() == KeyTypeEnum.Yubico) { // Server Sign
//                    KeyDownloadResponse keyDownload = ClientUtils.download(new KeyDownloadRequest(key.getKeyId(), key.getKeyPassword()));
//                    YubicoPassword yubico = MAPPER.readValue(keyDownload.getPrivateKey(), YubicoPassword.class);
//                    YubicoInfoResponse yubicoInfoResponse = ClientUtils.yubicoInfo();
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
//                SubordinateGenerateResponse response = ClientUtils.subordinateGenerate(new SubordinateGenerateRequest(new Issuer(issuerCertificateId, null, issuerKeyPassword), keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
//                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
//                if (response.getCertificate() != null) {
//                    System.out.println("wrote files");
//                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
//                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
//                }
    }

    // TODO
    public static void subordinateGenerateYubicoClientSign(String _key, String _subject, String output) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException, ApduException, ApplicationNotAvailableException, SignatureException, InvalidKeyException, InterruptedException {
        Key key = MAPPER.readValue(FileUtils.readFileToString(new File(_key), StandardCharsets.UTF_8), Key.class);
        AES256TextEncryptor encryptor = new AES256TextEncryptor();
        encryptor.setPassword(key.getKeyPassword());
        YubicoPassword yubico = MAPPER.readValue(encryptor.decrypt(key.getPrivateKey()), YubicoPassword.class);
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
            Crypto root = new Crypto(providers.get(serials.get(key.getKeyId())), key.getPublicKey(), rootPrivateKey);

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

            String signature = PrivateKeyUtils.signText(root.getProvider(), rootPrivateKey, key.getKeyId());

            RootRegisterRequest request = RootRegisterRequest.builder().build();
            request.setKey(Key.builder()
                    .keyId(key.getKeyId())
                    .keyPassword(StringUtils.split(signature, '.')[0])
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

            PivSession session = sessions.get(serials.get(key.getKeyId()));
            if (session != null) {
                Slot slot = slots.get(serials.get(key.getKeyId()));
                session.putCertificate(slot, rootCertificate);
            }

            RootRegisterResponse response = ClientUtils.rootRegister(request);
            if (response.getStatus() == 200) {
                Certificate certificate = Certificate.builder().build();
                certificate.setCertificate(response.getCertificate());
                certificate.setType(key.getType());
                certificate.setCertificateId(response.getCertificateId());
                certificate.setKeyPassword(response.getKeyPassword());
                if (output == null || output.isEmpty()) {
                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate));
                } else {
                    FileUtils.write(new File(output), MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate), StandardCharsets.UTF_8);
                }
            } else {
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            }
        } finally {
            for (SmartCardConnection connection : connections.values()) {
                if (connection != null) {
                    connection.close();
                }
            }
        }
    }

    public static void subordinateGenerateYubicoServerSign(String p, String p1, String p2) {
    }

}
