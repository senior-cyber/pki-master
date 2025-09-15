package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.client.cli.dto.BcClientGenerate;
import com.senior.cyber.pki.client.cli.dto.Subject;
import com.senior.cyber.pki.client.cli.dto.YubicoClientGenerate;
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
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
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
    public void run(String... args) throws IOException, InterruptedException, ApduException, ApplicationNotAvailableException, BadResponseException, NoSuchAlgorithmException {
        String api = System.getProperty("api");
        if ("key".equals(api)) {
            String function = System.getProperty("function");
            if ("bc-client-generate".equals(function)) {
                KeyFormat format = KeyFormat.valueOf(System.getProperty("format"));
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
                BcClientGenerate bcClientGenerate = new BcClientGenerate(keyPair.getPublic(), keyPair.getPrivate());
                System.out.println("wrote files");
                FileUtils.write(new File("key-info.json"), MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(bcClientGenerate), StandardCharsets.UTF_8);
                System.out.println("  " + "key-info.json");
                FileUtils.write(new File("public-key.pem"), PublicKeyUtils.convert(bcClientGenerate.getPublicKey()), StandardCharsets.UTF_8);
                System.out.println("  " + "public-key.pem");
                FileUtils.write(new File("private-key.pem"), PrivateKeyUtils.convert(bcClientGenerate.getPrivateKey()), StandardCharsets.UTF_8);
                System.out.println("  " + "private-key.pem");
                FileUtils.write(new File("openssh-public-key.pub"), OpenSshPublicKeyUtils.convert(bcClientGenerate.getPublicKey()), StandardCharsets.UTF_8);
                System.out.println("  " + "openssh-public-key.pub");
                FileUtils.write(new File("openssh-private-key"), OpenSshPrivateKeyUtils.convert(bcClientGenerate.getPrivateKey()), StandardCharsets.UTF_8);
                System.out.println("  " + "openssh-private-key");
            } else if ("bc-server-generate".equals(function)) {
                Integer size = Integer.parseInt(System.getProperty("size"));
                KeyFormat format = KeyFormat.valueOf(System.getProperty("format"));
                KeyGenerateResponse response = KeyUtils.bcGenerate(new BcKeyGenerateRequest(size, format));
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
            } else if ("yubico-server-generate".equals(function)) {
                Integer size = Integer.parseInt(System.getProperty("size"));
                String serialNumber = System.getProperty("serialNumber");
                String slot = System.getProperty("slot");
                String managementKey = System.getProperty("managementKey");
                KeyFormat format = KeyFormat.valueOf(System.getProperty("format"));
                KeyGenerateResponse response = KeyUtils.yubicoGenerate(new YubicoKeyGenerateRequest(size, format, serialNumber, slot, managementKey));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            } else if ("yubico-client-generate".equals(function)) {
                Integer size = Integer.parseInt(System.getProperty("size"));
                String serialNumber = System.getProperty("serialNumber");
                String _slot = System.getProperty("slot");
                String managementKey = System.getProperty("managementKey");
                if (managementKey == null || managementKey.isEmpty()) {
                    managementKey = MANAGEMENT_KEY;
                }
                Slot pivSlot = null;
                for (Slot slot : Slot.values()) {
                    if (slot.getStringAlias().equalsIgnoreCase(_slot)) {
                        pivSlot = slot;
                        break;
                    }
                }
                YubiKeyDevice device = YubicoProviderUtils.lookupDevice(serialNumber);
                try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                    PivSession session = new PivSession(connection);
                    session.authenticate(YubicoProviderUtils.hexStringToByteArray(managementKey));
                    PublicKey publicKey = null;
                    switch (size) {
                        case 1024 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.RSA1024);
                        }
                        case 2048 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.RSA2048);
                        }
                    }
                    YubicoClientGenerate yubicoClientGenerate = new YubicoClientGenerate(publicKey);
                    System.out.println("wrote files");
                    FileUtils.write(new File("key-info.json"), MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(yubicoClientGenerate), StandardCharsets.UTF_8);
                    System.out.println("  " + "key-info.json");
                    FileUtils.write(new File("public-key.pem"), PublicKeyUtils.convert(yubicoClientGenerate.getPublicKey()), StandardCharsets.UTF_8);
                    System.out.println("  " + "public-key.pem");
                    FileUtils.write(new File("openssh-public-key.pub"), OpenSshPublicKeyUtils.convert(yubicoClientGenerate.getPublicKey()), StandardCharsets.UTF_8);
                    System.out.println("  " + "openssh-public-key.pub");
                }
            } else if ("yubico-register".equals(function)) {
                Integer size = Integer.parseInt(System.getProperty("size"));
                String serialNumber = System.getProperty("serialNumber");
                String slot = System.getProperty("slot");
                String pin = System.getProperty("pin");
                String managementKey = System.getProperty("managementKey");
                KeyGenerateResponse response = KeyUtils.yubicoRegister(new YubicoKeyRegisterRequest(size, slot, serialNumber, managementKey, pin));
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
            if ("root-server-generate".equals(function)) {
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);
                RootServerGenerateResponse response = RootUtils.rootGenerate(new RootServerGenerateRequest(keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
                if (response.getCertificate() != null) {
                    System.out.println("wrote files");
                    FileUtils.write(new File(response.getCertificateId() + "-certificate.pem"), CertificateUtils.convert(response.getCertificate()), StandardCharsets.UTF_8);
                    System.out.println("  " + response.getCertificateId() + "-certificate.pem");
                }
            } else if ("root-client-generate".equals(function)) {
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);

                List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);
                JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
                JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerSubject, BigInteger.valueOf(serial), notBefore, notAfter, subject, publicKey);
                //        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
                //        builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKey));
                //        builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerPublicKey));
                //        if (keyUsages != null && !keyUsages.isEmpty()) {
                //            int keyUsage = 0;
                //            for (int ku : keyUsages) {
                //                keyUsage = keyUsage | ku;
                //            }
                //            builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
                //        }
                //        if (extendedKeyUsages != null && !extendedKeyUsages.isEmpty()) {
                //            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(extendedKeyUsages.toArray(new KeyPurposeId[0])));
                //        }
                //
                //        if (crl != null && !crl.isEmpty()) {
                //            List<DistributionPoint> distributionPoints = new ArrayList<>();
                //            if (crlIssuer == null || crlIssuer.isBlank()) {
                //                distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crl))), null, null));
                //            } else {
                //                GeneralNames _crlIssuer = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlIssuer));
                //                int reasonFlags = ReasonFlags.keyCompromise | ReasonFlags.cACompromise | ReasonFlags.affiliationChanged | ReasonFlags.superseded | ReasonFlags.cessationOfOperation | ReasonFlags.certificateHold | ReasonFlags.privilegeWithdrawn | ReasonFlags.aACompromise;
                //                distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crl))), new ReasonFlags(reasonFlags), _crlIssuer));
                //            }
                //            builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
                //        }
                //        if ((ocsp != null && !ocsp.isEmpty()) || (caIssuer != null && !caIssuer.isEmpty())) {
                //            List<AccessDescription> accessDescriptions = new ArrayList<>();
                //            if (ocsp != null && !ocsp.isEmpty()) {
                //                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, ocsp)));
                //            }
                //            if (caIssuer != null && !caIssuer.isEmpty()) {
                //                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, caIssuer)));
                //            }
                //            builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(accessDescriptions.toArray(new AccessDescription[0])));
                //        }
                //
                //        if (sans != null && !sans.isEmpty()) {
                //            List<String> included = new ArrayList<>();
                //            InetAddressValidator ipValidator = InetAddressValidator.getInstance();
                //            DomainValidator dnsValidator = DomainValidator.getInstance(true);
                //            List<GeneralName> generalNames = new ArrayList<>();
                //            for (String san : sans) {
                //                if (!included.contains(san)) {
                //                    if (ipValidator.isValid(san)) {
                //                        generalNames.add(new GeneralName(GeneralName.iPAddress, san));
                //                        included.add(san);
                //                    } else if (dnsValidator.isValid(san)) {
                //                        generalNames.add(new GeneralName(GeneralName.dNSName, san));
                //                        included.add(san);
                //                    }
                //                }
                //            }
                //            if (!generalNames.isEmpty()) {
                //                GeneralNames subjectAlternativeName = new GeneralNames(generalNames.toArray(new GeneralName[0]));
                //                try {
                //                    builder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeName);
                //                } catch (CertIOException e) {
                //                    throw new RuntimeException(e);
                //                }
                //            }
                //        }
                //
                //        String format = "";
                //        if (issuerPrivateKey instanceof RSAKey) {
                //            format = "RSA";
                //        } else if (issuerPrivateKey instanceof ECKey || "EC".equals(issuerPrivateKey.getAlgorithm())) {
                //            format = "ECDSA";
                //        } else {
                //            format = issuerPrivateKey.getAlgorithm();
                //        }
                //
                //        int shaSize = 256;
                //        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
                //        contentSignerBuilder.setProvider(issuerProvider);
                //        ContentSigner contentSigner = contentSignerBuilder.build(issuerPrivateKey);
                //
                //        X509CertificateHolder holder = builder.build(contentSigner);
                //        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
                //        certificateConverter.setProvider(X509_PROVIDER);
                //        return certificateConverter.getCertificate(holder);
                X509Certificate rootCertificate = PkiUtils.issueRootCa(root.getProvider(), root.getPrivateKey(), root.getPublicKey(), rootSubject, now.toDate(), now.plusYears(10).toDate(), System.currentTimeMillis());
                root.setCertificate(rootCertificate);
                Certificate _rootCertificate = new Certificate();
                _rootCertificate.setCountryCode(request.getCountry());
                _rootCertificate.setOrganization(request.getOrganization());
                _rootCertificate.setOrganizationalUnit(request.getOrganizationalUnit());
                _rootCertificate.setCommonName(request.getCommonName());
                _rootCertificate.setLocalityName(request.getLocality());
                _rootCertificate.setStateOrProvinceName(request.getProvince());
                _rootCertificate.setEmailAddress(request.getEmailAddress());
                _rootCertificate.setKey(rootKey);
                _rootCertificate.setCertificate(rootCertificate);
                _rootCertificate.setSerial(rootCertificate.getSerialNumber().longValueExact());
                _rootCertificate.setCreatedDatetime(new Date());
                _rootCertificate.setValidFrom(rootCertificate.getNotBefore());
                _rootCertificate.setValidUntil(rootCertificate.getNotAfter());
                _rootCertificate.setStatus(CertificateStatusEnum.Good);
                _rootCertificate.setType(CertificateTypeEnum.ROOT_CA);
                this.certificateRepository.save(_rootCertificate);

                // crl
                Key crlKey = null;
                {
                    KeyPair x509 = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormat.RSA);
                    Key key = new Key();
                    key.setStatus(KeyStatusEnum.Good);
                    key.setType(KeyTypeEnum.BC);
                    key.setKeySize(2048);
                    key.setKeyFormat(KeyFormat.RSA);
                    key.setPrivateKey(PrivateKeyUtils.convert(x509.getPrivate()));
                    key.setPublicKey(x509.getPublic());
                    key.setCreatedDatetime(new Date());
                    this.keyRepository.save(key);
                    crlKey = key;
                }
                X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(root.getProvider(), root.getPrivateKey(), root.getCertificate(), crlKey.getPublicKey(), rootSubject, now.toDate(), now.plusYears(1).toDate(), _rootCertificate.getSerial() + 1);
                Certificate crl = new Certificate();
                crl.setIssuerCertificate(_rootCertificate);
                crl.setCountryCode(request.getCountry());
                crl.setOrganization(request.getOrganization());
                crl.setOrganizationalUnit(request.getOrganizationalUnit());
                crl.setCommonName(request.getCommonName());
                crl.setLocalityName(request.getLocality());
                crl.setStateOrProvinceName(request.getProvince());
                crl.setEmailAddress(request.getEmailAddress());
                crl.setKey(crlKey);
                crl.setCertificate(crlCertificate);
                crl.setSerial(crlCertificate.getSerialNumber().longValueExact());
                crl.setCreatedDatetime(new Date());
                crl.setValidFrom(crlCertificate.getNotBefore());
                crl.setValidUntil(crlCertificate.getNotAfter());
                crl.setStatus(CertificateStatusEnum.Good);
                crl.setType(CertificateTypeEnum.CRL);
                this.certificateRepository.save(crl);

                // ocsp
                Key ocspKey = null;
                {
                    KeyPair x509 = com.senior.cyber.pki.common.x509.KeyUtils.generate(KeyFormat.RSA);
                    Key key = new Key();
                    key.setStatus(KeyStatusEnum.Good);
                    key.setType(KeyTypeEnum.BC);
                    key.setKeySize(2048);
                    key.setKeyFormat(KeyFormat.RSA);
                    key.setPrivateKey(PrivateKeyUtils.convert(x509.getPrivate()));
                    key.setPublicKey(x509.getPublic());
                    key.setCreatedDatetime(new Date());
                    this.keyRepository.save(key);
                    ocspKey = key;
                }
                X500Name ocspSubject = SubjectUtils.generate(
                        request.getCountry(),
                        request.getOrganization(),
                        request.getOrganizationalUnit(),
                        request.getCommonName() + " OCSP",
                        request.getLocality(),
                        request.getProvince(),
                        request.getEmailAddress()
                );
                X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(root.getProvider(), root.getPrivateKey(), root.getCertificate(), ocspKey.getPublicKey(), ocspSubject, now.toDate(), now.plusYears(1).toDate(), _rootCertificate.getSerial() + 2);
                Certificate ocsp = new Certificate();
                ocsp.setIssuerCertificate(_rootCertificate);
                ocsp.setCountryCode(request.getCountry());
                ocsp.setOrganization(request.getOrganization());
                ocsp.setOrganizationalUnit(request.getOrganizationalUnit());
                ocsp.setCommonName(request.getCommonName() + " OCSP");
                ocsp.setLocalityName(request.getLocality());
                ocsp.setStateOrProvinceName(request.getProvince());
                ocsp.setEmailAddress(request.getEmailAddress());
                ocsp.setKey(ocspKey);
                ocsp.setCertificate(ocspCertificate);
                ocsp.setSerial(ocspCertificate.getSerialNumber().longValueExact());
                ocsp.setCreatedDatetime(new Date());
                ocsp.setValidFrom(ocspCertificate.getNotBefore());
                ocsp.setValidUntil(ocspCertificate.getNotAfter());
                ocsp.setStatus(CertificateStatusEnum.Good);
                ocsp.setType(CertificateTypeEnum.OCSP);
                this.certificateRepository.save(ocsp);

                _rootCertificate.setCrlCertificate(crl);
                _rootCertificate.setOcspCertificate(_rootCertificate);
                this.certificateRepository.save(_rootCertificate);

                RootServerGenerateResponse response = new RootServerGenerateResponse();
                response.setCertificateId(_rootCertificate.getId());
                response.setKeyPassword(request.getKeyPassword());
                response.setCertificate(rootCertificate);

                PivSession session = sessions.get(serials.get(rootKey.getId()));
                if (session != null) {
                    Slot slot = slots.get(serials.get(rootKey.getId()));
                    session.putCertificate(slot, rootCertificate);
                }
            } else if ("root-client-register".equals(function)) {
                String keyId = System.getProperty("keyId");
                String keyPassword = System.getProperty("keyPassword");
                String subjectFile = System.getProperty("subject");
                String subjectText = FileUtils.readFileToString(new File(subjectFile), StandardCharsets.UTF_8);
                Subject subject = MAPPER.readValue(subjectText, Subject.class);
                RootServerGenerateResponse response = RootUtils.rootGenerate(new RootServerGenerateRequest(keyId, keyPassword, subject.getLocality(), subject.getProvince(), subject.getCountry(), subject.getCommonName(), subject.getOrganization(), subject.getOrganizationalUnit(), subject.getEmailAddress()));
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
