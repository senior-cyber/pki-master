package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.YubicoPivSlotEnum;
import com.senior.cyber.pki.dao.entity.rbac.User;

public interface CertificateService {

    CertificateCommonGenerateResponse certificateCommonGenerate(User user, CertificateCommonGenerateRequest request, String crlApi, String ocspApi, String x509Api, YubicoPivSlotEnum issuerPivSlot) throws InterruptedException;

    CertificateTlsGenerateResponse certificateTlsGenerate(User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api, YubicoPivSlotEnum issuerPivSlot) throws InterruptedException;

}
