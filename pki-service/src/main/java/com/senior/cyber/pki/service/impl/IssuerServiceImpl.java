package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.JcaIssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaIssuerGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoIssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.YubicoIssuerGenerateResponse;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.IssuerService;
import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class IssuerServiceImpl implements IssuerService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public JcaIssuerGenerateResponse issuerGenerate(User user, JcaIssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) {
        Date now = LocalDate.now().toDate();

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Issuer) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }
        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            Provider issuerProvider = new BouncyCastleProvider();
            PrivateKey issuerPrivateKey = issuerKey.getPrivateKey();
            return issuingIssuer(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getIssuerSerialNumber());
            if (device == null) {
                throw new IllegalArgumentException("device not found");
            }
            JcaIssuerGenerateResponse response = null;
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                try (PivSession session = new PivSession(connection)) {
                    try {
                        session.authenticate(YubicoProviderUtils.hexStringToByteArray(request.getIssuerManagementKey()));
                    } catch (IOException | ApduException | BadResponseException e) {
                        throw new RuntimeException(e);
                    }
                    Provider issuerProvider = new PivProvider(session);
                    KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                    PrivateKey issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, request.getIssuerPin());

                    response = issuingIssuer(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
                    return response;
                } catch (IOException | ApduException | ApplicationNotAvailableException e) {
                    throw new RuntimeException(e);
                }
            } catch (Exception e) {
                if (e instanceof java.lang.IllegalStateException && "Exclusive access not assigned to current Thread".equals(e.getMessage())) {
                    return response;
                } else {
                    throw new RuntimeException(e);
                }
            }
        } else {
            throw new IllegalArgumentException("issuerKey not found");
        }
    }

    @Transactional(rollbackFor = Throwable.class)
    protected JcaIssuerGenerateResponse issuingIssuer(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, JcaIssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api) {
        // issuing
        Key issuingKey = null;
        Provider issuingProvider = new BouncyCastleProvider();
        PrivateKey issuingPrivateKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            issuingPrivateKey = x509.getPrivate();
            Key key = new Key();
            key.setUser(user);
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPublicKey(x509.getPublic());
            key.setPrivateKey(x509.getPrivate());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);
            issuingKey = key;
        }

        X500Name issuingSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        long serial = System.currentTimeMillis();

        X509Certificate issuingCertificate = IssuerUtils.generate(issuerProvider, issuerCertificate.getCertificate(), issuerPrivateKey, issuingKey.getPublicKey(), issuingSubject, crlApi, ocspApi, x509Api, serial);
        Certificate issuing = new Certificate();
        issuing.setIssuerCertificate(issuerCertificate);
        issuing.setCountryCode(request.getCountry());
        issuing.setOrganization(request.getOrganization());
        issuing.setOrganizationalUnit(request.getOrganizationalUnit());
        issuing.setCommonName(request.getCommonName());
        issuing.setLocalityName(request.getLocality());
        issuing.setStateOrProvinceName(request.getProvince());
        issuing.setEmailAddress(request.getEmailAddress());
        issuing.setKey(issuingKey);
        issuing.setCertificate(issuingCertificate);
        issuing.setSerial(serial);
        issuing.setCreatedDatetime(new Date());
        issuing.setValidFrom(issuingCertificate.getNotBefore());
        issuing.setValidUntil(issuingCertificate.getNotAfter());
        issuing.setStatus(CertificateStatusEnum.Good);
        issuing.setType(CertificateTypeEnum.Issuer);
        issuing.setUser(user);
        this.certificateRepository.save(issuing);

        // crl
        Key crlKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setUser(user);
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);
            crlKey = key;
        }
        X500Name crlSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest crlCsr = CsrUtils.generate(new KeyPair(crlKey.getPublicKey(), crlKey.getPrivateKey()), crlSubject);
        X509Certificate crlCertificate = IssuerUtils.generateCrlCertificate(issuingProvider, issuingCertificate, issuingPrivateKey, crlCsr, serial + 1);
        Certificate crl = new Certificate();
        crl.setIssuerCertificate(issuing);
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
        crl.setType(CertificateTypeEnum.Crl);
        crl.setUser(user);
        this.certificateRepository.save(crl);

        // ocsp
        Key ocspKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setUser(user);
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPrivateKey(x509.getPrivate());
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
        PKCS10CertificationRequest ocspCsr = CsrUtils.generate(new KeyPair(ocspKey.getPublicKey(), ocspKey.getPrivateKey()), ocspSubject);
        X509Certificate ocspCertificate = IssuerUtils.generateOcspCertificate(issuingProvider, issuingCertificate, issuingPrivateKey, ocspCsr, serial + 2);
        Certificate ocsp = new Certificate();
        ocsp.setIssuerCertificate(issuing);
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
        ocsp.setType(CertificateTypeEnum.Ocsp);
        ocsp.setUser(user);
        this.certificateRepository.save(ocsp);

        issuing.setCrlCertificate(crl);
        issuing.setOcspCertificate(ocsp);
        this.certificateRepository.save(issuing);

        JcaIssuerGenerateResponse response = new JcaIssuerGenerateResponse();
        response.setId(issuing.getId());
        response.setCertificate(issuingCertificate);
        response.setPublicKey(issuingKey.getPublicKey());
        response.setPrivateKey(issuingPrivateKey);
        response.setOcspCertificate(ocspCertificate);
        response.setOcspPublicKey(ocspCertificate.getPublicKey());
        response.setOcspPrivateKey(ocspKey.getPrivateKey());
        response.setCrlCertificate(crlCertificate);
        response.setCrlPublicKey(crlKey.getPublicKey());
        response.setCrlPrivateKey(crlKey.getPrivateKey());

        return response;
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public YubicoIssuerGenerateResponse issuerGenerate(User user, YubicoIssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot, Slot pivSlot) {
        Date now = LocalDate.now().toDate();

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Issuer) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }

        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            Provider issuerProvider = new BouncyCastleProvider();
            PrivateKey issuerPrivateKey = issuerKey.getPrivateKey();
            return issuingIssuer(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, pivSlot, crlApi, ocspApi, x509Api);
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getIssuerSerialNumber());
            if (device == null) {
                throw new IllegalArgumentException("device not found");
            }
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                try (PivSession session = new PivSession(connection)) {
                    try {
                        session.authenticate(YubicoProviderUtils.hexStringToByteArray(request.getIssuerManagementKey()));
                    } catch (IOException | ApduException | BadResponseException e) {
                        throw new RuntimeException(e);
                    }
                    Provider issuerProvider = new PivProvider(session);
                    KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                    PrivateKey issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, request.getIssuerPin());

                    return issuingIssuer(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, pivSlot, crlApi, ocspApi, x509Api);
                } catch (IOException | ApduException | ApplicationNotAvailableException e) {
                    throw new RuntimeException(e);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }
    }

    @Transactional(rollbackFor = Throwable.class)
    protected YubicoIssuerGenerateResponse issuingIssuer(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, YubicoIssuerGenerateRequest request, Slot pivSlot, String crlApi, String ocspApi, String x509Api) {
        YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getSerialNumber());
        if (device == null) {
            throw new IllegalArgumentException("device not found");
        }

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            try (PivSession session = new PivSession(connection)) {
                try {
                    session.authenticate(YubicoProviderUtils.hexStringToByteArray(request.getManagementKey()));
                } catch (IOException | ApduException | BadResponseException e) {
                    throw new RuntimeException(e);
                }

                PublicKey publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.RSA2048);

                Provider issuingProvider = new PivProvider(session);
                KeyStore keyStore = YubicoProviderUtils.lookupKeyStore(issuingProvider);
                PrivateKey privateKey = YubicoProviderUtils.lookupPrivateKey(keyStore, pivSlot, request.getPin());


                // issuing
                Key issuingKey = null;
                PrivateKey issuingPrivateKey = privateKey;
                {
                    KeyPair x509 = new KeyPair(publicKey, privateKey);
                    Key key = new Key();
                    key.setType(KeyTypeEnum.ServerKeyYubico);
                    key.setPublicKey(x509.getPublic());
                    key.setCreatedDatetime(new Date());
                    key.setUser(user);
                    this.keyRepository.save(key);
                    issuingKey = key;
                }

                X500Name issuingSubject = SubjectUtils.generate(
                        request.getCountry(),
                        request.getOrganization(),
                        request.getOrganizationalUnit(),
                        request.getCommonName(),
                        request.getLocality(),
                        request.getProvince(),
                        request.getEmailAddress()
                );
                long serial = System.currentTimeMillis();
                X509Certificate issuingCertificate = IssuerUtils.generate(issuerProvider, issuerCertificate.getCertificate(), issuerPrivateKey, issuingKey.getPublicKey(), issuingSubject, crlApi, ocspApi, x509Api, serial);
                Certificate issuing = new Certificate();
                issuing.setIssuerCertificate(issuerCertificate);
                issuing.setCountryCode(request.getCountry());
                issuing.setOrganization(request.getOrganization());
                issuing.setOrganizationalUnit(request.getOrganizationalUnit());
                issuing.setCommonName(request.getCommonName());
                issuing.setLocalityName(request.getLocality());
                issuing.setStateOrProvinceName(request.getProvince());
                issuing.setEmailAddress(request.getEmailAddress());
                issuing.setKey(issuingKey);
                issuing.setCertificate(issuingCertificate);
                issuing.setSerial(serial);
                issuing.setCreatedDatetime(new Date());
                issuing.setValidFrom(issuingCertificate.getNotBefore());
                issuing.setValidUntil(issuingCertificate.getNotAfter());
                issuing.setStatus(CertificateStatusEnum.Good);
                issuing.setType(CertificateTypeEnum.Issuer);
                issuing.setUser(user);
                this.certificateRepository.save(issuing);

                // crl
                Key crlKey = null;
                {
                    KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
                    Key key = new Key();
                    key.setType(KeyTypeEnum.ServerKeyJCE);
                    key.setUser(user);
                    key.setPrivateKey(x509.getPrivate());
                    key.setPublicKey(x509.getPublic());
                    key.setCreatedDatetime(new Date());
                    this.keyRepository.save(key);
                    crlKey = key;
                }
                X500Name crlSubject = SubjectUtils.generate(
                        request.getCountry(),
                        request.getOrganization(),
                        request.getOrganizationalUnit(),
                        request.getCommonName(),
                        request.getLocality(),
                        request.getProvince(),
                        request.getEmailAddress()
                );
                PKCS10CertificationRequest crlCsr = CsrUtils.generate(new KeyPair(crlKey.getPublicKey(), crlKey.getPrivateKey()), crlSubject);
                X509Certificate crlCertificate = IssuerUtils.generateCrlCertificate(issuingProvider, issuingCertificate, issuingPrivateKey, crlCsr, serial + 1);
                Certificate crl = new Certificate();
                crl.setIssuerCertificate(issuing);
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
                crl.setType(CertificateTypeEnum.Crl);
                crl.setUser(user);
                this.certificateRepository.save(crl);

                // ocsp
                Key ocspKey = null;
                {
                    KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
                    Key key = new Key();
                    key.setUser(user);
                    key.setType(KeyTypeEnum.ServerKeyJCE);
                    key.setPrivateKey(x509.getPrivate());
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
                PKCS10CertificationRequest ocspCsr = CsrUtils.generate(new KeyPair(ocspKey.getPublicKey(), ocspKey.getPrivateKey()), ocspSubject);
                X509Certificate ocspCertificate = IssuerUtils.generateOcspCertificate(issuingProvider, issuingCertificate, issuingPrivateKey, ocspCsr, serial + 2);
                Certificate ocsp = new Certificate();
                ocsp.setIssuerCertificate(issuing);
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
                ocsp.setType(CertificateTypeEnum.Ocsp);
                ocsp.setUser(user);
                this.certificateRepository.save(ocsp);

                issuing.setCrlCertificate(crl);
                issuing.setOcspCertificate(ocsp);
                this.certificateRepository.save(issuing);

                YubicoIssuerGenerateResponse response = new YubicoIssuerGenerateResponse();
                response.setId(issuing.getId());
                response.setCertificate(issuingCertificate);
                response.setPublicKey(issuingKey.getPublicKey());
                response.setSlot(pivSlot.getStringAlias());
                response.setSerialNumber(request.getSerialNumber());
                response.setOcspCertificate(ocspCertificate);
                response.setOcspPublicKey(ocspCertificate.getPublicKey());
                response.setOcspPrivateKey(ocspKey.getPrivateKey());
                response.setCrlCertificate(crlCertificate);
                response.setCrlPublicKey(crlKey.getPublicKey());
                response.setCrlPrivateKey(crlKey.getPrivateKey());

                session.putCertificate(pivSlot, issuingCertificate);

                return response;
            } catch (IOException | ApduException | ApplicationNotAvailableException e) {
                throw new RuntimeException(e);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
