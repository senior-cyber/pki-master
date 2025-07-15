package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.JcaRootGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaRootGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateRequest;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateResponse;
import com.senior.cyber.pki.common.x509.YubicoPivSlotEnum;
import com.senior.cyber.pki.dao.entity.rbac.User;

public interface RootService {

    JcaRootGenerateResponse rootGenerate(User user, JcaRootGenerateRequest request) throws InterruptedException;

    YubicoRootGenerateResponse rootGenerate(User user, YubicoRootGenerateRequest request, YubicoPivSlotEnum pivSlot) throws InterruptedException;

}
