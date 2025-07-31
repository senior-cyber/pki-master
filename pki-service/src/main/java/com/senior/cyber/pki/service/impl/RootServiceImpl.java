package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.RootGenerateRequest;
import com.senior.cyber.pki.common.dto.RootGenerateResponse;
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
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
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
    public RootGenerateResponse rootGenerate(User user, RootGenerateRequest request, String sshApi) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException {
        Provider provider = null;
        SmartCardConnection connection = null;
        PivSession session = null;
        Slot slot = null;

        // root
        Key rootKey = this.keyRepository.findById(request.getKeyId()).orElseThrow();
        PrivateKey rootPrivateKey = null;
        if (rootKey.getType() == KeyTypeEnum.ClientKey) {
            provider = new BouncyCastleProvider();
            if (request.getPrivateKey() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else {
                rootPrivateKey = request.getPrivateKey();
            }
        } else if (rootKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            provider = new BouncyCastleProvider();
            rootPrivateKey = rootKey.getPrivateKey();
        } else if (rootKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(rootKey.getYubicoSerial());
            connection = device.openConnection(SmartCardConnection.class);
            session = new PivSession(connection);
            provider = new PivProvider(session);
            KeyStore ks = YubicoProviderUtils.lookupKeyStore(provider);
            for (Slot s : Slot.values()) {
                if (s.getStringAlias().equalsIgnoreCase(rootKey.getYubicoPivSlot())) {
                    slot = s;
                    break;
                }
            }
            rootPrivateKey = YubicoProviderUtils.lookupPrivateKey(ks, slot, rootKey.getYubicoPin());
        }

        LocalDate now = LocalDate.now();

        try {
            X500Name rootSubject = SubjectUtils.generate(
                    request.getCountry(),
                    request.getOrganization(),
                    request.getOrganizationalUnit(),
                    request.getCommonName(),
                    request.getLocality(),
                    request.getProvince(),
                    request.getEmailAddress()
            );

            X509Certificate rootCertificate = PkiUtils.issueRootCertificate(provider, rootPrivateKey, rootKey.getPublicKey(), rootSubject, now.toDate(), now.plusYears(10).toDate(), System.currentTimeMillis());
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
                key.setKeySize(2048);
                key.setKeyFormat(KeyFormat.RSA);
                key.setPrivateKey(x509.getPrivate());
                key.setPublicKey(x509.getPublic());
                key.setCreatedDatetime(new Date());
                key.setUser(user);
                this.keyRepository.save(key);
                crlKey = key;
            }
            X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(provider, rootPrivateKey, rootCertificate, crlKey.getPublicKey(), rootSubject, now.toDate(), now.plusYears(1).toDate(), root.getSerial() + 1);
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
                key.setKeySize(2048);
                key.setKeyFormat(KeyFormat.RSA);
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
            X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(provider, rootPrivateKey, rootCertificate, ocspKey.getPublicKey(), ocspSubject, now.toDate(), now.plusYears(1).toDate(), root.getSerial() + 2);
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

            RootGenerateResponse response = new RootGenerateResponse();
            response.setId(root.getId());
            response.setCertificate(rootCertificate);
            response.setCertificateBase64(Base64.getEncoder().encodeToString(CertificateUtils.convert(rootCertificate).getBytes(StandardCharsets.UTF_8)));
            response.setPublicKey(rootKey.getPublicKey());
            response.setPrivateKey(rootPrivateKey);
            response.setPrivateKeyBase64(Base64.getEncoder().encodeToString(PrivateKeyUtils.convert(rootPrivateKey).getBytes(StandardCharsets.UTF_8)));
            response.setOcspCertificate(ocspCertificate);
            response.setOcspPublicKey(ocspCertificate.getPublicKey());
            response.setOcspPrivateKey(ocspKey.getPrivateKey());
            response.setCrlCertificate(crlCertificate);
            response.setCrlPublicKey(crlKey.getPublicKey());
            response.setCrlPrivateKey(crlKey.getPrivateKey());
            String hex = String.format("%012X", rootCertificate.getSerialNumber().longValue());
            response.setSshCa(sshApi + "/openssh/" + hex + ".pub");

            if (session != null) {
                session.putCertificate(slot, rootCertificate);
            }

            return response;
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

}
