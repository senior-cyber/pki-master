package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.JcaIssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaIssuerGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoIssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.YubicoIssuerGenerateResponse;
import com.senior.cyber.pki.common.x509.YubicoPivSlotEnum;
import com.senior.cyber.pki.dao.entity.rbac.User;

public interface IssuerService {

    JcaIssuerGenerateResponse issuerGenerate(User user, JcaIssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api, YubicoPivSlotEnum issuerPivSlot) throws InterruptedException;

    YubicoIssuerGenerateResponse issuerGenerate(User user, YubicoIssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api, YubicoPivSlotEnum issuerPivSlot, YubicoPivSlotEnum pivSlot) throws InterruptedException;

}
