package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.*;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;

public interface KeyService {

    KeyGenerateResponse generate(BcKeyGenerateRequest request) throws OperatorCreationException;

    KeyGenerateResponse generate(YubicoKeyGenerateRequest request) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException;

    KeyGenerateResponse register(YubicoKeyRegisterRequest request) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}
