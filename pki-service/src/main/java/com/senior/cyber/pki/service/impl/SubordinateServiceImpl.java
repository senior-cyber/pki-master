package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.SubordinateGenerateRequest;
import com.senior.cyber.pki.common.dto.SubordinateGenerateResponse;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.*;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.SubordinateService;
import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class SubordinateServiceImpl implements SubordinateService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public SubordinateGenerateResponse subordinateGenerate(SubordinateGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws IOException, ApduException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException {
        Provider issuerProvider = null;
        Provider provider = null;
        Map<String, SmartCardConnection> connections = new HashMap<>();
        Map<String, KeyStore> keys = new HashMap<>();
        Map<String, Slot> slots = new HashMap<>();
        Map<String, PivSession> sessions = new HashMap<>();

        // issuer
        Certificate _issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "certificate is not found"));
        Key _issuerKey = this.keyRepository.findById(_issuerCertificate.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        X509Certificate issuerCertificate = _issuerCertificate.getCertificate();
        PrivateKey issuerPrivateKey = null;
        switch (_issuerKey.getType()) {
            case ServerKeyJCE -> {
                issuerProvider = new BouncyCastleProvider();
                issuerPrivateKey = PrivateKeyUtils.convert(_issuerKey.getPrivateKey(), request.getIssuer().getKeyPassword());
            }
            case ServerKeyYubico -> {
                YubiKeyDevice device = YubicoProviderUtils.lookupDevice(_issuerKey.getYubicoSerial());
                SmartCardConnection connection = device.openConnection(SmartCardConnection.class);
                connections.put(_issuerKey.getYubicoSerial(), connection);
                PivSession session = new PivSession(connection);
                session.authenticate(YubicoProviderUtils.hexStringToByteArray(_issuerKey.getYubicoManagementKey()));
                sessions.put(_issuerKey.getYubicoSerial(), session);
                issuerProvider = new PivProvider(session);
                KeyStore ks = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                keys.put(_issuerKey.getYubicoSerial(), ks);
                Slot slot = null;
                for (Slot s : Slot.values()) {
                    if (s.getStringAlias().equalsIgnoreCase(_issuerKey.getYubicoPivSlot())) {
                        slot = s;
                        break;
                    }
                }
                issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(ks, slot, _issuerKey.getYubicoPin());
            }
        }

        Key _intermediateKey = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        PublicKey publicKey = _intermediateKey.getPublicKey();
        PrivateKey privateKey = null;
        switch (_intermediateKey.getType()) {
            case ServerKeyJCE -> {
                provider = new BouncyCastleProvider();
                privateKey = PrivateKeyUtils.convert(_intermediateKey.getPrivateKey(), request.getKeyPassword());
            }
            case ServerKeyYubico -> {
                SmartCardConnection connection = null;
                KeyStore ks = null;
                if (!connections.containsKey(_intermediateKey.getYubicoSerial())) {
                    YubiKeyDevice device = YubicoProviderUtils.lookupDevice(_intermediateKey.getYubicoSerial());
                    connection = device.openConnection(SmartCardConnection.class);
                    connections.put(_intermediateKey.getYubicoSerial(), connection);
                    PivSession session = new PivSession(connection);
                    session.authenticate(YubicoProviderUtils.hexStringToByteArray(_intermediateKey.getYubicoManagementKey()));
                    sessions.put(_intermediateKey.getYubicoSerial(), session);
                    provider = new PivProvider(session);
                    ks = YubicoProviderUtils.lookupKeyStore(provider);
                } else {
                    provider = issuerProvider;
                    ks = keys.get(_intermediateKey.getYubicoSerial());
                }
                Slot slot = null;
                for (Slot s : Slot.values()) {
                    if (s.getStringAlias().equalsIgnoreCase(_intermediateKey.getYubicoPivSlot())) {
                        slot = s;
                        break;
                    }
                }
                slots.put(_intermediateKey.getYubicoSerial(), slot);
                privateKey = YubicoProviderUtils.lookupPrivateKey(ks, slot, _intermediateKey.getYubicoPin());
            }
        }

        try {
            LocalDate now = LocalDate.now();

            X500Name subject = SubjectUtils.generate(
                    request.getCountry(),
                    request.getOrganization(),
                    request.getOrganizationalUnit(),
                    request.getCommonName(),
                    request.getLocality(),
                    request.getProvince(),
                    request.getEmailAddress()
            );
            long serial = System.currentTimeMillis();
            X509Certificate subordinateCertificate = PkiUtils.issueSubordinateCA(issuerProvider, issuerPrivateKey, issuerCertificate, crlApi, ocspApi, x509Api, null, publicKey, subject, now.toDate(), now.plusYears(5).toDate(), serial);
            Certificate subordinate = new Certificate();
            subordinate.setIssuerCertificate(_issuerCertificate);
            subordinate.setCountryCode(request.getCountry());
            subordinate.setOrganization(request.getOrganization());
            subordinate.setOrganizationalUnit(request.getOrganizationalUnit());
            subordinate.setCommonName(request.getCommonName());
            subordinate.setLocalityName(request.getLocality());
            subordinate.setStateOrProvinceName(request.getProvince());
            subordinate.setEmailAddress(request.getEmailAddress());
            subordinate.setKey(_intermediateKey);
            subordinate.setCertificate(subordinateCertificate);
            subordinate.setSerial(serial);
            subordinate.setCreatedDatetime(new Date());
            subordinate.setValidFrom(subordinateCertificate.getNotBefore());
            subordinate.setValidUntil(subordinateCertificate.getNotAfter());
            subordinate.setStatus(CertificateStatusEnum.Good);
            subordinate.setType(CertificateTypeEnum.SUBORDINATE_CA);
            this.certificateRepository.save(subordinate);

            // crl
            Key crlKey = null;
            {
                KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
                Key key = new Key();
                key.setStatus(KeyStatusEnum.Good);
                key.setType(KeyTypeEnum.ServerKeyJCE);
                key.setKeySize(2048);
                key.setKeyFormat(KeyFormat.RSA);
                key.setPrivateKey(PrivateKeyUtils.convert(x509.getPrivate()));
                key.setPublicKey(x509.getPublic());
                key.setCreatedDatetime(new Date());
                this.keyRepository.save(key);
                crlKey = key;
            }
            X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(provider, privateKey, subordinateCertificate, crlKey.getPublicKey(), subject, now.toDate(), now.plusYears(1).toDate(), serial + 1);
            Certificate crl = new Certificate();
            crl.setIssuerCertificate(subordinate);
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
                KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
                Key key = new Key();
                key.setStatus(KeyStatusEnum.Good);
                key.setType(KeyTypeEnum.ServerKeyJCE);
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
            X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(provider, privateKey, subordinateCertificate, ocspKey.getPublicKey(), ocspSubject, now.toDate(), now.plusYears(1).toDate(), serial + 2);
            Certificate ocsp = new Certificate();
            ocsp.setIssuerCertificate(subordinate);
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

            subordinate.setCrlCertificate(crl);
            subordinate.setOcspCertificate(ocsp);
            this.certificateRepository.save(subordinate);

            SubordinateGenerateResponse response = new SubordinateGenerateResponse();
            response.setCertificateId(subordinate.getId());
            response.setKeyPassword(request.getKeyPassword());
            response.setCertificate(subordinateCertificate);

            PivSession session = sessions.get(_intermediateKey.getYubicoSerial());
            if (session != null) {
                session.putCertificate(slots.get(_intermediateKey.getYubicoSerial()), subordinateCertificate);
            }
            return response;
        } finally {
            for (SmartCardConnection connection : connections.values()) {
                connection.close();
            }
        }
    }
}
