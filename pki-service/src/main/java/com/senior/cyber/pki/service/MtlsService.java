package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.MtlsCertificateGenerateRequest;
import com.senior.cyber.pki.common.dto.MtlsCertificateGenerateResponse;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface MtlsService {

    MtlsCertificateGenerateResponse mtlsGenerate(MtlsCertificateGenerateRequest request) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}
