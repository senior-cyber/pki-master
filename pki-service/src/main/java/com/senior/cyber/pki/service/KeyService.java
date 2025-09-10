package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;

public interface KeyService {

    JcaKeyGenerateResponse generate(JcaKeyGenerateRequest request) throws OperatorCreationException;

    YubicoKeyGenerateResponse generate(YubicoKeyGenerateRequest request) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException;

    YubicoKeyRegisterResponse register(YubicoKeyRegisterRequest request) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}
