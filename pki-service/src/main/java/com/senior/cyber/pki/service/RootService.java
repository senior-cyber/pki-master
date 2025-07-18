package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.JcaRootGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaRootGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateRequest;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateResponse;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.piv.Slot;

public interface RootService {

    JcaRootGenerateResponse rootGenerate(User user, JcaRootGenerateRequest request, String x509Api);

    YubicoRootGenerateResponse rootGenerate(User user, YubicoRootGenerateRequest request, Slot pivSlot, String x509Api);

}
