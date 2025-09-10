package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.MtlsGenerateRequest;
import com.senior.cyber.pki.common.dto.MtlsGenerateResponse;
import com.senior.cyber.pki.common.x509.PkiUtils;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.common.x509.SubjectUtils;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.MtlsService;
import com.senior.cyber.pki.service.Utils;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class MtlsServiceImpl implements MtlsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MtlsServiceImpl.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public MtlsGenerateResponse mtlsGenerate(MtlsGenerateRequest request) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Provider provider = null;
        SmartCardConnection connection = null;
        PivSession session = null;
        Slot slot = null;

        // root
        Key rootKey = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        PrivateKey rootPrivateKey = null;
        switch (rootKey.getType()) {
            case ServerKeyYubico -> {
                YubiKeyDevice device = YubicoProviderUtils.lookupDevice(rootKey.getYubicoSerial());
                connection = device.openConnection(SmartCardConnection.class);
                session = new PivSession(connection);
                session.authenticate(YubicoProviderUtils.hexStringToByteArray(rootKey.getYubicoManagementKey()));
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
            case ServerKeyJCE -> {
                provider = Utils.BC;
                rootPrivateKey = PrivateKeyUtils.convert(rootKey.getPrivateKey(), request.getKeyPassword());
            }
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
                    null
            );

            X509Certificate rootCertificate = PkiUtils.mtlsServerCertificate(provider, rootPrivateKey, rootKey.getPublicKey(), rootSubject, now.toDate(), now.plusYears(10).toDate(), System.currentTimeMillis());
            Certificate root = new Certificate();
            root.setCountryCode(request.getCountry());
            root.setOrganization(request.getOrganization());
            root.setOrganizationalUnit(request.getOrganizationalUnit());
            root.setCommonName(request.getCommonName());
            root.setLocalityName(request.getLocality());
            root.setStateOrProvinceName(request.getProvince());
            root.setKey(rootKey);
            root.setCertificate(rootCertificate);
            root.setSerial(rootCertificate.getSerialNumber().longValueExact());
            root.setCreatedDatetime(new Date());
            root.setValidFrom(rootCertificate.getNotBefore());
            root.setValidUntil(rootCertificate.getNotAfter());
            root.setStatus(CertificateStatusEnum.Good);
            root.setType(CertificateTypeEnum.mTLS_SERVER);
            this.certificateRepository.save(root);

            MtlsGenerateResponse response = new MtlsGenerateResponse();
            response.setCertificateId(root.getId());
            response.setKeyPassword(request.getKeyPassword());
            response.setCertificate(rootCertificate);

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
