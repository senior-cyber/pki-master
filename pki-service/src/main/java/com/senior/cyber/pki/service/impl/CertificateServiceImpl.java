package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.CertificateService;
import com.senior.cyber.pki.service.util.OpenSshCertificateBuilder;
import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyEncryptionContext;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.common.util.io.output.SecureByteArrayOutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class CertificateServiceImpl implements CertificateService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public LeafGenerateResponse leafGenerate(User user, LeafGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Date _now = LocalDate.now().toDate();

        Certificate _issuerCertificate = this.certificateRepository.findById(request.getIssuerCertificateId()).orElseThrow();
        if (_issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (_issuerCertificate.getType() != CertificateTypeEnum.Root && _issuerCertificate.getType() != CertificateTypeEnum.Intermediate) ||
                _issuerCertificate.getValidFrom().after(_now) ||
                _issuerCertificate.getValidUntil().before(_now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerCertificateId() + " is not valid");
        }

        X509Certificate issuerCertificate = _issuerCertificate.getCertificate();

        Key issuerKey = this.keyRepository.findById(_issuerCertificate.getKey().getId()).orElseThrow();

        SmartCardConnection connection = null;

        Provider issuerProvider = null;
        PrivateKey issuerPrivateKey = null;
        if (issuerKey.getType() == KeyTypeEnum.ClientKey) {
            issuerProvider = new BouncyCastleProvider();
            issuerPrivateKey = request.getIssuerPrivateKey();
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            issuerProvider = new BouncyCastleProvider();
            issuerPrivateKey = issuerKey.getPrivateKey();
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(issuerKey.getYubicoSerial());
            if (device == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "device not found");
            }
            connection = device.openConnection(SmartCardConnection.class);
            PivSession session = new PivSession(connection);
            session.authenticate(YubicoProviderUtils.hexStringToByteArray(issuerKey.getYubicoManagementKey()));
            issuerProvider = new PivProvider(session);
            KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
            Slot slot = null;
            for (Slot s : Slot.values()) {
                if (s.getStringAlias().equalsIgnoreCase(issuerKey.getYubicoPivSlot())) {
                    slot = s;
                    break;
                }
            }
            issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, slot, issuerKey.getYubicoPin());
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        try {
            Key certificateKey = null;
            PublicKey publicKey = null;
            if (request.getKeyId() != null) {
                certificateKey = this.keyRepository.findById(request.getKeyId()).orElseThrow();
                if (certificateKey.getType() == KeyTypeEnum.ServerKeyYubico) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getKeyId() + " is not support");
                }
                publicKey = certificateKey.getPublicKey();
            } else {
                if (request.getPublicKey() != null) {
                    publicKey = request.getPublicKey();

                    // certificate
                    certificateKey = new Key();
                    certificateKey.setUser(user);
                    certificateKey.setType(KeyTypeEnum.ClientKey);
                    certificateKey.setPublicKey(publicKey);
                    certificateKey.setCreatedDatetime(new Date());
                    if (publicKey instanceof RSAKey) {
                        certificateKey.setKeyFormat(KeyFormat.RSA);
                    } else if (publicKey instanceof ECKey) {
                        certificateKey.setKeyFormat(KeyFormat.EC);
                    }
                    this.keyRepository.save(certificateKey);
                } else {
                    KeyPair x509 = KeyUtils.generate(request.getKeyFormat(), request.getKeySize());
                    publicKey = x509.getPublic();

                    // certificate
                    certificateKey = new Key();
                    certificateKey.setUser(user);
                    certificateKey.setKeySize(request.getKeySize());
                    certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
                    if (publicKey instanceof RSAKey) {
                        certificateKey.setKeyFormat(KeyFormat.RSA);
                    } else if (publicKey instanceof ECKey) {
                        certificateKey.setKeyFormat(KeyFormat.EC);
                    }
                    certificateKey.setPublicKey(x509.getPublic());
                    certificateKey.setPrivateKey(x509.getPrivate());
                    certificateKey.setCreatedDatetime(new Date());
                    this.keyRepository.save(certificateKey);
                }
            }

            LocalDate now = LocalDate.now();
            X500Name subject = SubjectUtils.generate(request.getCountry(), request.getOrganization(), request.getOrganizationalUnit(), request.getCommonName(), request.getLocality(), request.getProvince(), request.getEmailAddress());
            X509Certificate leafCertificate = PkiUtils.issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, crlApi, ocspApi, x509Api, null, publicKey, subject, now.toDate(), now.plusYears(1).toDate(), System.currentTimeMillis(), null, null, null);
            Certificate certificate = new Certificate();
            certificate.setIssuerCertificate(_issuerCertificate);
            certificate.setCountryCode(request.getCountry());
            certificate.setOrganization(request.getOrganization());
            certificate.setOrganizationalUnit(request.getOrganizationalUnit());
            certificate.setCommonName(request.getCommonName());
            certificate.setLocalityName(request.getLocality());
            certificate.setStateOrProvinceName(request.getProvince());
            certificate.setEmailAddress(request.getEmailAddress());
            certificate.setKey(certificateKey);
            certificate.setCertificate(leafCertificate);
            certificate.setSerial(leafCertificate.getSerialNumber().longValueExact());
            certificate.setCreatedDatetime(new Date());
            certificate.setValidFrom(leafCertificate.getNotBefore());
            certificate.setValidUntil(leafCertificate.getNotAfter());
            certificate.setStatus(CertificateStatusEnum.Good);
            certificate.setType(CertificateTypeEnum.Leaf);
            certificate.setUser(user);
            this.certificateRepository.save(certificate);

            LeafGenerateResponse response = new LeafGenerateResponse();
            response.setId(certificate.getId());
            response.setCert(leafCertificate);
            response.setCertBase64(Base64.getEncoder().encodeToString(CertificateUtils.convert(leafCertificate).getBytes(StandardCharsets.UTF_8)));
            response.setPrivkey(certificateKey.getPrivateKey());
            response.setPrivkeyBase64(Base64.getEncoder().encodeToString(PrivateKeyUtils.convert(certificateKey.getPrivateKey()).getBytes(StandardCharsets.UTF_8)));

            List<X509Certificate> chain = new ArrayList<>();
            chain.add(issuerCertificate);

            Certificate temp = _issuerCertificate;
            while (true) {
                String id = temp.getIssuerCertificate().getId();
                Certificate cert = this.certificateRepository.findById(id).orElse(null);
                if (cert == null) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.Root) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.Intermediate) {
                    chain.add(cert.getCertificate());
                    temp = cert;
                }
            }
            response.setChain(chain);

            List<X509Certificate> fullchain = new ArrayList<>();
            fullchain.add(certificate.getCertificate());
            temp = certificate;
            while (true) {
                String id = temp.getIssuerCertificate().getId();
                Certificate cert = this.certificateRepository.findById(id).orElse(null);
                if (cert == null) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.Root) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.Intermediate) {
                    fullchain.add(cert.getCertificate());
                    temp = cert;
                }
            }
            response.setFullchain(fullchain);
            response.setKeyId(certificateKey.getId());
            return response;
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

    @Override
    public LeafGenerateResponse serverGenerate(User user, ServerCertificateGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Date _now = LocalDate.now().toDate();

        Certificate _issuerCertificate = this.certificateRepository.findById(request.getIssuerCertificateId()).orElseThrow();
        if (_issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (_issuerCertificate.getType() != CertificateTypeEnum.Root && _issuerCertificate.getType() != CertificateTypeEnum.Intermediate) ||
                _issuerCertificate.getValidFrom().after(_now) ||
                _issuerCertificate.getValidUntil().before(_now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerCertificateId() + " is not valid");
        }

        X509Certificate issuerCertificate = _issuerCertificate.getCertificate();

        Key issuerKey = this.keyRepository.findById(_issuerCertificate.getKey().getId()).orElseThrow();

        SmartCardConnection connection = null;

        Provider issuerProvider = null;
        PrivateKey issuerPrivateKey = null;
        if (issuerKey.getType() == KeyTypeEnum.ClientKey) {
            issuerProvider = new BouncyCastleProvider();
            issuerPrivateKey = request.getIssuerPrivateKey();
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            issuerProvider = new BouncyCastleProvider();
            issuerPrivateKey = issuerKey.getPrivateKey();
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(issuerKey.getYubicoSerial());
            if (device == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "device not found");
            }
            connection = device.openConnection(SmartCardConnection.class);
            PivSession session = new PivSession(connection);
            session.authenticate(YubicoProviderUtils.hexStringToByteArray(issuerKey.getYubicoManagementKey()));
            issuerProvider = new PivProvider(session);
            KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
            Slot slot = null;
            for (Slot s : Slot.values()) {
                if (s.getStringAlias().equalsIgnoreCase(issuerKey.getYubicoPivSlot())) {
                    slot = s;
                    break;
                }
            }
            issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, slot, issuerKey.getYubicoPin());
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        try {
            Key certificateKey = null;
            PublicKey publicKey = null;
            if (request.getKeyId() != null) {
                certificateKey = this.keyRepository.findById(request.getKeyId()).orElseThrow();
                if (certificateKey.getType() == KeyTypeEnum.ServerKeyYubico) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getKeyId() + " is not support");
                }
                publicKey = certificateKey.getPublicKey();
            } else {
                if (request.getPublicKey() != null) {
                    publicKey = request.getPublicKey();

                    // certificate
                    certificateKey = new Key();
                    certificateKey.setUser(user);
                    certificateKey.setType(KeyTypeEnum.ClientKey);
                    certificateKey.setPublicKey(publicKey);
                    certificateKey.setCreatedDatetime(new Date());
                    if (publicKey instanceof RSAKey) {
                        certificateKey.setKeyFormat(KeyFormat.RSA);
                    } else if (publicKey instanceof ECKey) {
                        certificateKey.setKeyFormat(KeyFormat.EC);
                    }
                    this.keyRepository.save(certificateKey);
                } else {
                    KeyPair x509 = KeyUtils.generate(request.getKeyFormat(), request.getKeySize());
                    publicKey = x509.getPublic();

                    // certificate
                    certificateKey = new Key();
                    certificateKey.setUser(user);
                    certificateKey.setKeySize(request.getKeySize());
                    certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
                    if (publicKey instanceof RSAKey) {
                        certificateKey.setKeyFormat(KeyFormat.RSA);
                    } else if (publicKey instanceof ECKey) {
                        certificateKey.setKeyFormat(KeyFormat.EC);
                    }
                    certificateKey.setPublicKey(x509.getPublic());
                    certificateKey.setPrivateKey(x509.getPrivate());
                    certificateKey.setCreatedDatetime(new Date());
                    this.keyRepository.save(certificateKey);
                }
            }

            LocalDate now = LocalDate.now();
            X500Name subject = SubjectUtils.generate(request.getCountry(), request.getOrganization(), request.getOrganizationalUnit(), request.getCommonName(), request.getLocality(), request.getProvince(), request.getEmailAddress());
            List<Integer> keyUsages = new ArrayList<>();
            keyUsages.add(KeyUsage.digitalSignature);
            if (request.getKeyFormat() == KeyFormat.RSA) {
                keyUsages.add(KeyUsage.keyEncipherment);
            } else if (request.getKeyFormat() == KeyFormat.EC) {
                keyUsages.add(KeyUsage.keyEncipherment);
                keyUsages.add(KeyUsage.keyAgreement);
            }
            List<KeyPurposeId> extendedKeyUsages = new ArrayList<>();
            extendedKeyUsages.add(KeyPurposeId.id_kp_serverAuth);
            List<String> sans = request.getSans();
            X509Certificate leafCertificate = PkiUtils.issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, crlApi, ocspApi, x509Api, null, publicKey, subject, now.toDate(), now.plusYears(1).toDate(), System.currentTimeMillis(), keyUsages, extendedKeyUsages, sans);
            Certificate certificate = new Certificate();
            certificate.setIssuerCertificate(_issuerCertificate);
            certificate.setCountryCode(request.getCountry());
            certificate.setOrganization(request.getOrganization());
            certificate.setOrganizationalUnit(request.getOrganizationalUnit());
            certificate.setCommonName(request.getCommonName());
            certificate.setLocalityName(request.getLocality());
            certificate.setStateOrProvinceName(request.getProvince());
            certificate.setEmailAddress(request.getEmailAddress());
            certificate.setKey(certificateKey);
            certificate.setCertificate(leafCertificate);
            certificate.setSerial(leafCertificate.getSerialNumber().longValueExact());
            certificate.setCreatedDatetime(new Date());
            certificate.setValidFrom(leafCertificate.getNotBefore());
            certificate.setValidUntil(leafCertificate.getNotAfter());
            certificate.setStatus(CertificateStatusEnum.Good);
            certificate.setType(CertificateTypeEnum.Leaf);
            certificate.setUser(user);
            this.certificateRepository.save(certificate);

            LeafGenerateResponse response = new LeafGenerateResponse();
            response.setId(certificate.getId());
            response.setCert(leafCertificate);
            response.setCertBase64(Base64.getEncoder().encodeToString(CertificateUtils.convert(leafCertificate).getBytes(StandardCharsets.UTF_8)));
            response.setPrivkey(certificateKey.getPrivateKey());
            response.setPrivkeyBase64(Base64.getEncoder().encodeToString(PrivateKeyUtils.convert(certificateKey.getPrivateKey()).getBytes(StandardCharsets.UTF_8)));

            List<X509Certificate> chain = new ArrayList<>();
            chain.add(issuerCertificate);

            Certificate temp = _issuerCertificate;
            while (true) {
                String id = temp.getIssuerCertificate().getId();
                Certificate cert = this.certificateRepository.findById(id).orElse(null);
                if (cert == null) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.Root) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.Intermediate) {
                    chain.add(cert.getCertificate());
                    temp = cert;
                }
            }
            response.setChain(chain);

            List<X509Certificate> fullchain = new ArrayList<>();
            fullchain.add(certificate.getCertificate());
            temp = certificate;
            while (true) {
                String id = temp.getIssuerCertificate().getId();
                Certificate cert = this.certificateRepository.findById(id).orElse(null);
                if (cert == null) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.Root) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.Intermediate) {
                    fullchain.add(cert.getCertificate());
                    temp = cert;
                }
            }
            response.setFullchain(fullchain);
            response.setKeyId(certificateKey.getId());
            return response;
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

    @Override
    public LeafGenerateResponse clientGenerate(User user, LeafGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, BadResponseException, ApduException, ApplicationNotAvailableException {
        return leafGenerate(user, request, crlApi, ocspApi, x509Api);
    }

    @Override
    @Transactional
    public SshCertificateGenerateResponse sshGenerate(User user, SshCertificateGenerateRequest request) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Key _issuerKey = this.keyRepository.findById(request.getIssuerKeyId()).orElseThrow();
//        uhlvvIBiBdvHDLuvjUHrTInvGGigCgilfhcBTj
//        uhlvvIBiBdvHDLuvjUHrTInvGGigCgilfhcBTj
//        2326da3c099d0e2edf1d611b0e3d716de28f1396

        SmartCardConnection connection = null;

        KeyPair issuerKey = null;
        Provider issuerProvider = null;
        if (_issuerKey.getType() == KeyTypeEnum.ClientKey) {
            issuerProvider = new BouncyCastleProvider();
            issuerKey = new KeyPair(_issuerKey.getPublicKey(), request.getIssuerPrivateKey());
        } else if (_issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            issuerProvider = new BouncyCastleProvider();
            issuerKey = new KeyPair(_issuerKey.getPublicKey(), _issuerKey.getPrivateKey());
        } else if (_issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(_issuerKey.getYubicoSerial());
            if (device == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "device not found");
            }
            connection = device.openConnection(SmartCardConnection.class);
            PivSession session = new PivSession(connection);
            session.authenticate(YubicoProviderUtils.hexStringToByteArray(_issuerKey.getYubicoManagementKey()));
            issuerProvider = new PivProvider(session);
            KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
            Slot slot = null;
            for (Slot s : Slot.values()) {
                if (s.getStringAlias().equalsIgnoreCase(_issuerKey.getYubicoPivSlot())) {
                    slot = s;
                    break;
                }
            }
            PrivateKey issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, slot, _issuerKey.getYubicoPin());
            issuerKey = new KeyPair(_issuerKey.getPublicKey(), issuerPrivateKey);
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerKeyId() + " is not valid");
        }

        if ((request.getPrincipal() == null || request.getPrincipal().isEmpty())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "principal required");
        }

        try {
            PublicKey publicKey = null;
            PrivateKey privateKey = null;
            if (request.getOpensshPublicKey() != null && !request.getOpensshPublicKey().isBlank()) {
                List<AuthorizedKeyEntry> authorizedKeyEntries = null;
                try {
                    authorizedKeyEntries = AuthorizedKeyEntry.readAuthorizedKeys(new ByteArrayInputStream(request.getOpensshPublicKey().getBytes(StandardCharsets.UTF_8)), true);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                try {
                    publicKey = authorizedKeyEntries.getFirst().resolvePublicKey(null, PublicKeyEntryResolver.IGNORING);
                } catch (IOException | GeneralSecurityException e) {
                    throw new RuntimeException(e);
                }
            } else {
                KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
                publicKey = x509.getPublic();
                privateKey = x509.getPrivate();
            }

            OpenSshCertificateBuilder openSshCertificateBuilder = OpenSshCertificateBuilder.userCertificate();
            openSshCertificateBuilder.provider(issuerProvider);
            openSshCertificateBuilder.id(UUID.randomUUID().toString());
            openSshCertificateBuilder.serial(System.currentTimeMillis());
            openSshCertificateBuilder.extensions(Arrays.asList(
                    new OpenSshCertificate.CertificateOption("permit-user-rc"),
                    new OpenSshCertificate.CertificateOption("permit-X11-forwarding"),
                    new OpenSshCertificate.CertificateOption("permit-agent-forwarding"),
                    new OpenSshCertificate.CertificateOption("permit-port-forwarding"),
                    new OpenSshCertificate.CertificateOption("permit-pty")));
            openSshCertificateBuilder.principals(List.of(request.getPrincipal()));
            openSshCertificateBuilder.publicKey(publicKey);
            openSshCertificateBuilder.validAfter(Instant.now());
            if (request.getValidityPeriod() <= 0) {
                openSshCertificateBuilder.validBefore(Instant.now().plus(10, ChronoUnit.MINUTES));
            } else if (request.getValidityPeriod() > 480) {
                openSshCertificateBuilder.validBefore(Instant.now().plus(480, ChronoUnit.MINUTES));
            } else {
                openSshCertificateBuilder.validBefore(Instant.now().plus(request.getValidityPeriod(), ChronoUnit.MINUTES));
            }
            OpenSshCertificate certificate = null;
            try {
                certificate = openSshCertificateBuilder.sign(issuerKey, org.apache.sshd.common.config.keys.KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            SshCertificateGenerateResponse response = new SshCertificateGenerateResponse();
            response.setOpensshCertificate(PublicKeyEntry.toString(certificate));

            if (privateKey != null) {
                try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
                    OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(new KeyPair(publicKey, privateKey), "", new OpenSSHKeyEncryptionContext(), out);
                    response.setOpensshPrivateKey(out.toString(StandardCharsets.UTF_8));
                } catch (IOException | GeneralSecurityException e) {
                    throw new RuntimeException(e);
                }
            }

            response.setOpensshConfig("Host " + request.getServer() + "\n" +
                    "  HostName " + request.getServer() + "\n" +
                    "  User " + request.getPrincipal() + "\n" +
                    "  IdentityFile pk\n" +
                    "  CertificateFile pk-cert.pub");
            return response;
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

}
