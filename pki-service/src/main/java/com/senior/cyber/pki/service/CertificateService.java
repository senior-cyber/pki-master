package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.CertificateCommonGenerateRequest;
import com.senior.cyber.pki.common.dto.CertificateCommonGenerateResponse;
import com.senior.cyber.pki.common.dto.CertificateTlsGenerateRequest;
import com.senior.cyber.pki.common.dto.CertificateTlsGenerateResponse;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.piv.Slot;

public interface CertificateService {

    CertificateCommonGenerateResponse certificateCommonGenerate(User user, CertificateCommonGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot);

    CertificateTlsGenerateResponse certificateTlsServerGenerate(User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot);

    CertificateTlsGenerateResponse certificateTlsClientGenerate(User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot);

}
