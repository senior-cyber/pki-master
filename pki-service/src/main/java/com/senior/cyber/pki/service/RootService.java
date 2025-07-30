package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.JcaRootGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaRootGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateRequest;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateResponse;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.yubico.yubikit.piv.Slot;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface RootService {

    JcaRootGenerateResponse rootGenerate(User user, JcaRootGenerateRequest request, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException, PEMException;

    YubicoRootGenerateResponse rootGenerate(User user, YubicoRootGenerateRequest request, Slot pivSlot, String x509Api);

}
