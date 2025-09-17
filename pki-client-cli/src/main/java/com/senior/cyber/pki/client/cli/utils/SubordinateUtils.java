package com.senior.cyber.pki.client.cli.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.client.cli.ClientProgram;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.*;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.DateTime;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SubordinateUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void subordinateGenerate(String _issuer, String _key, String _subject, String output) throws IOException, InterruptedException, CertificateException, NoSuchAlgorithmException, OperatorCreationException {
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
                System.out.println("test");
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

}
