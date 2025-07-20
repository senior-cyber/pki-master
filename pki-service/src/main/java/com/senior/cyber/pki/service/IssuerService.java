package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.piv.Slot;

public interface IssuerService {

    JcaIssuerGenerateResponse issuerGenerate(User user, JcaIssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api, String sshApi, Slot issuerPivSlot);

    YubicoIssuerGenerateResponse issuerGenerate(User user, YubicoIssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api, String sshApi, Slot issuerPivSlot, Slot pivSlot);

}
