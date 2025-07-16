package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.JcaRootGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaRootGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateRequest;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateResponse;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.RootService;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class RootServiceImpl implements RootService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RootServiceImpl.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public JcaRootGenerateResponse rootGenerate(User user, JcaRootGenerateRequest request) {
        Provider provider = new BouncyCastleProvider();
        // root
        Key rootKey = null;
        PrivateKey rootPrivateKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPublicKey(x509.getPublic());
            key.setPrivateKey(x509.getPrivate());
            key.setCreatedDatetime(new Date());
            key.setUser(user);
            this.keyRepository.save(key);
            rootKey = key;
            rootPrivateKey = x509.getPrivate();
        }

        X500Name rootSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        X509Certificate rootCertificate = RootUtils.generate(provider, rootPrivateKey, rootKey.getPublicKey(), rootSubject);
        Certificate root = new Certificate();
        root.setCountryCode(request.getCountry());
        root.setOrganization(request.getOrganization());
        root.setOrganizationalUnit(request.getOrganizationalUnit());
        root.setCommonName(request.getCommonName());
        root.setLocalityName(request.getLocality());
        root.setStateOrProvinceName(request.getProvince());
        root.setEmailAddress(request.getEmailAddress());
        root.setKey(rootKey);
        root.setCertificate(rootCertificate);
        root.setSerial(rootCertificate.getSerialNumber().longValueExact());
        root.setCreatedDatetime(new Date());
        root.setValidFrom(rootCertificate.getNotBefore());
        root.setValidUntil(rootCertificate.getNotAfter());
        root.setStatus(CertificateStatusEnum.Good);
        root.setType(CertificateTypeEnum.Root);
        root.setUser(user);
        this.certificateRepository.save(root);

        // crl
        Key crlKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setCreatedDatetime(new Date());
            key.setUser(user);
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
        X509Certificate crlCertificate = IssuerUtils.generateCrlCertificate(provider, rootCertificate, rootPrivateKey, crlCsr, root.getSerial() + 1);
        Certificate crl = new Certificate();
        crl.setIssuerCertificate(root);
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
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setCreatedDatetime(new Date());
            key.setUser(user);
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
        X509Certificate ocspCertificate = IssuerUtils.generateOcspCertificate(provider, rootCertificate, rootPrivateKey, ocspCsr, root.getSerial() + 2);
        Certificate ocsp = new Certificate();
        ocsp.setIssuerCertificate(root);
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

        root.setCrlCertificate(crl);
        root.setOcspCertificate(ocsp);
        this.certificateRepository.save(root);

        JcaRootGenerateResponse response = new JcaRootGenerateResponse();
        response.setId(root.getId());
        response.setCertificate(rootCertificate);
        response.setPublicKey(rootKey.getPublicKey());
        response.setPrivateKey(rootPrivateKey);
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
    public YubicoRootGenerateResponse rootGenerate(User user, YubicoRootGenerateRequest request, Slot pivSlot) {
        YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getSerialNumber());
        if (device == null) {
            throw new RuntimeException("Device not found");
        }
        YubicoRootGenerateResponse response = null;
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            try (PivSession session = new PivSession(connection)) {
                try {
                    session.authenticate(YubicoProviderUtils.hexStringToByteArray(request.getManagementKey()));
                } catch (IOException | ApduException | BadResponseException e) {
                    throw new RuntimeException(e);
                }
                PublicKey publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.RSA2048);
                if (publicKey == null) {
                    throw new RuntimeException("Public key not found");
                }

                Provider provider = new PivProvider(session);
                KeyStore ks = YubicoProviderUtils.lookupKeyStore(provider);
                if (ks == null) {
                    throw new RuntimeException("KeyStore not found");
                }

                PrivateKey privateKey = YubicoProviderUtils.lookupPrivateKey(ks, pivSlot, request.getPin());

                // root
                Key rootKey = null;
                PrivateKey rootPrivateKey = null;
                {
                    KeyPair x509 = new KeyPair(publicKey, privateKey);
                    Key key = new Key();
                    key.setType(KeyTypeEnum.ServerKeyYubico);
                    key.setPublicKey(x509.getPublic());
                    key.setCreatedDatetime(new Date());
                    key.setUser(user);
                    this.keyRepository.save(key);
                    rootKey = key;
                    rootPrivateKey = x509.getPrivate();
                }

                X500Name rootSubject = SubjectUtils.generate(
                        request.getCountry(),
                        request.getOrganization(),
                        request.getOrganizationalUnit(),
                        request.getCommonName(),
                        request.getLocality(),
                        request.getProvince(),
                        request.getEmailAddress()
                );
                X509Certificate rootCertificate = RootUtils.generate(provider, rootPrivateKey, rootKey.getPublicKey(), rootSubject);
                Certificate root = new Certificate();
                root.setCountryCode(request.getCountry());
                root.setOrganization(request.getOrganization());
                root.setOrganizationalUnit(request.getOrganizationalUnit());
                root.setCommonName(request.getCommonName());
                root.setLocalityName(request.getLocality());
                root.setStateOrProvinceName(request.getProvince());
                root.setEmailAddress(request.getEmailAddress());
                root.setKey(rootKey);
                root.setCertificate(rootCertificate);
                root.setSerial(rootCertificate.getSerialNumber().longValueExact());
                root.setCreatedDatetime(new Date());
                root.setValidFrom(rootCertificate.getNotBefore());
                root.setValidUntil(rootCertificate.getNotAfter());
                root.setStatus(CertificateStatusEnum.Good);
                root.setType(CertificateTypeEnum.Root);
                root.setUser(user);
                this.certificateRepository.save(root);

                // crl
                Key crlKey = null;
                {
                    KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
                    Key key = new Key();
                    key.setType(KeyTypeEnum.ServerKeyJCE);
                    key.setPrivateKey(x509.getPrivate());
                    key.setPublicKey(x509.getPublic());
                    key.setCreatedDatetime(new Date());
                    key.setUser(user);
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
                X509Certificate crlCertificate = IssuerUtils.generateCrlCertificate(provider, rootCertificate, rootPrivateKey, crlCsr, root.getSerial() + 1);
                Certificate crl = new Certificate();
                crl.setIssuerCertificate(root);
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
                    key.setType(KeyTypeEnum.ServerKeyJCE);
                    key.setPrivateKey(x509.getPrivate());
                    key.setPublicKey(x509.getPublic());
                    key.setCreatedDatetime(new Date());
                    key.setUser(user);
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
                X509Certificate ocspCertificate = IssuerUtils.generateOcspCertificate(provider, rootCertificate, rootPrivateKey, ocspCsr, root.getSerial() + 2);
                Certificate ocsp = new Certificate();
                ocsp.setIssuerCertificate(root);
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

                root.setCrlCertificate(crl);
                root.setOcspCertificate(ocsp);
                this.certificateRepository.save(root);

                response = new YubicoRootGenerateResponse();
                response.setId(root.getId());
                response.setCertificate(rootCertificate);
                response.setPublicKey(rootKey.getPublicKey());
                response.setSlot(pivSlot.getStringAlias());
                response.setSerialNumber(request.getSerialNumber());
                response.setOcspCertificate(ocspCertificate);
                response.setOcspPublicKey(ocspCertificate.getPublicKey());
                response.setOcspPrivateKey(ocspKey.getPrivateKey());
                response.setCrlCertificate(crlCertificate);
                response.setCrlPublicKey(crlKey.getPublicKey());
                response.setCrlPrivateKey(crlKey.getPrivateKey());

                session.putCertificate(pivSlot, rootCertificate);
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
    }

}
