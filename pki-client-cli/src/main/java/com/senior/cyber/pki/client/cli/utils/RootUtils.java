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
import org.joda.time.LocalDate;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;


public class RootUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static void rootGenerateBcClientSign(Key key, String subject) throws ApduException, IOException, InterruptedException, BadResponseException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, SignatureException, InvalidKeyException {
        Subject _subject = MAPPER.readValue(FileUtils.readFileToString(new File(subject), StandardCharsets.UTF_8), Subject.class);
        X500Name rootSubject = SubjectUtils.generate(_subject.getCountry(),
                _subject.getOrganization(),
                _subject.getOrganizationalUnit(),
                _subject.getCommonName(),
                _subject.getLocality(),
                _subject.getProvince(),
                _subject.getEmailAddress());

        PublicKey rootPublicKey = key.getPublicKey();
        PrivateKey rootPrivateKey = PrivateKeyUtils.convert(key.getPrivateKey());
        if (rootPrivateKey == null) {
            throw new RuntimeException("root private key is not found");
        }

        LocalDate now = LocalDate.now();

        long rootSerial = System.currentTimeMillis();
        X509Certificate rootCertificate = PkiUtils.issueRootCa(ClientProgram.PROVIDER, rootPrivateKey, rootPublicKey, rootSubject, now.toDate(), now.plusYears(10).toDate(), rootSerial);

        KeyPair crlKey = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA, 2048);
        PublicKey crlPublicKey = crlKey.getPublic();
        PrivateKey crlPrivateKey = crlKey.getPrivate();
        X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(ClientProgram.PROVIDER, rootPrivateKey, rootCertificate, crlPublicKey, rootSubject, now.toDate(), now.plusYears(1).toDate(), rootSerial + 1);

        X500Name ocspSubject = SubjectUtils.generate(
                _subject.getCountry(),
                _subject.getOrganization(),
                _subject.getOrganizationalUnit(),
                _subject.getCommonName() + " OCSP",
                _subject.getLocality(),
                _subject.getProvince(),
                _subject.getEmailAddress()
        );
        KeyPair ocspKey = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA, 2048);
        PublicKey ocspPublicKey = ocspKey.getPublic();
        PrivateKey ocspPrivateKey = ocspKey.getPrivate();
        X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(ClientProgram.PROVIDER, rootPrivateKey, rootCertificate, ocspPublicKey, ocspSubject, now.toDate(), now.plusYears(1).toDate(), rootSerial + 2);

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

        RootRegisterResponse response = ClientUtils.rootRegister(request);
        if (response.getCertificate() != null) {
            Certificate certificate = Certificate.builder().build();
            certificate.setCertificateId(response.getCertificateId());
            certificate.setKeyId(response.getKeyId());
            certificate.setKeyPassword(response.getKeyPassword());
            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate));
        }
    }

    private static void rootGenerateBcServerSign(Key key, String _subject) throws ApduException, IOException, InterruptedException, BadResponseException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, SignatureException, InvalidKeyException {
        Subject subject = MAPPER.readValue(FileUtils.readFileToString(new File(_subject), StandardCharsets.UTF_8), Subject.class);
        RootGenerateResponse response = ClientUtils.rootGenerate(RootGenerateRequest.builder()
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
            certificate.setKeyId(response.getKeyId());
            certificate.setKeyPassword(response.getKeyPassword());
            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate));
        }
    }

    public static void rootGenerateYubicoClientSign(String key, String subject, String output) throws ApduException, IOException, InterruptedException, BadResponseException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, SignatureException, InvalidKeyException {
        Key _key = MAPPER.readValue(FileUtils.readFileToString(new File(key), StandardCharsets.UTF_8), Key.class);
        AES256TextEncryptor encryptor = new AES256TextEncryptor();
        encryptor.setPassword(_key.getKeyPassword());
        YubicoPassword yubico = MAPPER.readValue(encryptor.decrypt(_key.getPrivateKey()), YubicoPassword.class);
        Map<String, SmartCardConnection> connections = new HashMap<>();
        Map<String, KeyStore> keys = new HashMap<>();
        Map<String, PivProvider> providers = new HashMap<>();
        Map<String, PivSession> sessions = new HashMap<>();
        Map<String, Slot> slots = new HashMap<>();
        Map<String, String> serials = new HashMap<>();

        try {
            Subject _subject = MAPPER.readValue(FileUtils.readFileToString(new File(subject), StandardCharsets.UTF_8), Subject.class);
            X500Name rootSubject = SubjectUtils.generate(_subject.getCountry(),
                    _subject.getOrganization(),
                    _subject.getOrganizationalUnit(),
                    _subject.getCommonName(),
                    _subject.getLocality(),
                    _subject.getProvince(),
                    _subject.getEmailAddress());

            PrivateKey rootPrivateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, _key.getKeyId(), yubico);
            Crypto root = new Crypto(providers.get(serials.get(_key.getKeyId())), _key.getPublicKey(), rootPrivateKey);

            LocalDate now = LocalDate.now();

            long rootSerial = System.currentTimeMillis();
            X509Certificate rootCertificate = PkiUtils.issueRootCa(root.getProvider(), root.getPrivateKey(), root.getPublicKey(), rootSubject, now.toDate(), now.plusYears(10).toDate(), rootSerial);

            KeyPair crlKey = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA, 2048);
            PublicKey crlPublicKey = crlKey.getPublic();
            PrivateKey crlPrivateKey = crlKey.getPrivate();
            X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(root.getProvider(), root.getPrivateKey(), rootCertificate, crlPublicKey, rootSubject, now.toDate(), now.plusYears(1).toDate(), rootSerial + 1);

            X500Name ocspSubject = SubjectUtils.generate(
                    _subject.getCountry(),
                    _subject.getOrganization(),
                    _subject.getOrganizationalUnit(),
                    _subject.getCommonName() + " OCSP",
                    _subject.getLocality(),
                    _subject.getProvince(),
                    _subject.getEmailAddress()
            );
            KeyPair ocspKey = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormatEnum.RSA, 2048);
            PublicKey ocspPublicKey = ocspKey.getPublic();
            PrivateKey ocspPrivateKey = ocspKey.getPrivate();
            X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(root.getProvider(), root.getPrivateKey(), rootCertificate, ocspPublicKey, ocspSubject, now.toDate(), now.plusYears(1).toDate(), rootSerial + 2);

            String signature = PrivateKeyUtils.signText(root.getProvider(), rootPrivateKey, _key.getKeyId());

            RootRegisterRequest request = RootRegisterRequest.builder().build();
            request.setKey(Key.builder()
                    .keyId(_key.getKeyId())
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

            PivSession session = sessions.get(serials.get(_key.getKeyId()));
            if (session != null) {
                Slot slot = slots.get(serials.get(_key.getKeyId()));
                session.putCertificate(slot, rootCertificate);
            }

            RootRegisterResponse response = ClientUtils.rootRegister(request);
            if (response.getStatus() == 200) {
                Certificate certificate = Certificate.builder().build();
                certificate.setCertificate(response.getCertificate());
                certificate.setType(_key.getType());
                certificate.setKeyId(response.getKeyId());
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

    private static void rootGenerateYubicoServerSign(String key, String subject) throws ApduException, IOException, InterruptedException, BadResponseException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, SignatureException, InvalidKeyException {
        Key _key = MAPPER.readValue(FileUtils.readFileToString(new File(key), StandardCharsets.UTF_8), Key.class);
        Subject _subject = MAPPER.readValue(FileUtils.readFileToString(new File(subject), StandardCharsets.UTF_8), Subject.class);
        RootGenerateResponse response = ClientUtils.rootGenerate(RootGenerateRequest.builder()
                .key(Key.builder()
                        .keyId(_key.getKeyId())
                        .keyPassword(_key.getKeyPassword())
                        .build())
                .subject(_subject).build());
        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
        if (response.getCertificate() != null) {
            Certificate certificate = Certificate.builder().build();
            certificate.setCertificateId(response.getCertificateId());
            certificate.setKeyId(response.getKeyId());
            certificate.setType(_key.getType());
            certificate.setDecentralized(_key.isDecentralized());
            certificate.setKeyPassword(response.getKeyPassword());
            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(certificate));
        }
    }

    public static void rootGenerate(String key, String subject) throws ApduException, IOException, InterruptedException, BadResponseException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, SignatureException, InvalidKeyException {
        Key _key = MAPPER.readValue(FileUtils.readFileToString(new File(key), StandardCharsets.UTF_8), Key.class);
        if (_key.getType() == KeyTypeEnum.BC) {
            if (_key.isDecentralized()) { // Client Sign
                rootGenerateBcClientSign(_key, subject);
            } else { // Server Sign
                rootGenerateBcServerSign(_key, subject);
            }
        } else if (_key.getType() == KeyTypeEnum.Yubico) {
            YubicoInfoResponse yubicoInfoResponse = ClientUtils.yubicoInfo();
            if (yubicoInfoResponse.getItems() != null && !yubicoInfoResponse.getItems().isEmpty()) {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(_key.getKeyPassword());
                YubicoPassword yubico = MAPPER.readValue(encryptor.decrypt(_key.getPrivateKey()), YubicoPassword.class);
                boolean found = false;
                for (YubicoInfo item : yubicoInfoResponse.getItems()) {
                    if (item.getSerialNumber().equals(yubico.getSerial())) {
                        found = true;
                        if ("client".equals(item.getType())) { // Client Sign
                            rootGenerateYubicoClientSign(key, subject, null);
                        } else if ("server".equals(item.getType())) { // Server Sign
                            rootGenerateYubicoServerSign(key, subject);
                        }
                    }
                }
                if (!found) {
                    throw new RuntimeException("root private key is not found");
                }
            }
        }

    }

}
