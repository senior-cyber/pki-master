package com.senior.cyber.pki.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.senior.cyber.pki.common.dto.*;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;

public interface KeyService {

    KeyGenerateResponse bcGenerate(BcGenerateRequest request) throws OperatorCreationException, JsonProcessingException;

    KeyGenerateResponse bcRegister(BcRegisterRequest request) throws JsonProcessingException;

    KeyGenerateResponse yubicoGenerate(YubicoGenerateRequest request) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException;

    KeyGenerateResponse yubicoRegister(YubicoRegisterRequest request) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException;

}
