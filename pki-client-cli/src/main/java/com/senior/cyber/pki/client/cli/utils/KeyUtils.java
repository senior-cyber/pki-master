package com.senior.cyber.pki.client.cli.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.dto.Key;
import com.senior.cyber.pki.common.util.YubicoProviderUtils;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.jasypt.util.text.AES256TextEncryptor;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class KeyUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void bcServerGenerate(String _size, String _format, String emailAddress) throws IOException, InterruptedException {
        int size = Integer.parseInt(_size);
        KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
        KeyGenerateResponse response = ClientUtils.bcServerGenerate(BcGenerateRequest.builder().size(size).format(format).emailAddress(emailAddress).build());
        if (response.getStatus() == 200) {
            Key key = Key.builder().build();
            key.setKeyId(response.getKeyId());
            key.setKeyPassword(response.getKeyPassword());
            key.setPublicKey(response.getOpenSshPublicKey());
            key.setSize(size);
            key.setFormat(format);
            key.setType(KeyTypeEnum.BC);
            key.setDecentralized(false);
            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key));
        } else {
            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
        }
    }

    public static void bcClientGenerate(Provider provider, String _format, String emailAddress) throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
        int keySize = 0;
        switch (format) {
            case EC -> {
                keySize = 384;
            }
            case RSA -> {
                keySize = 2048;
            }
        }
        KeyPair keyPair = com.senior.cyber.pki.common.x509.KeyUtils.generate(format, keySize);
        BcRegisterRequest request = BcRegisterRequest.builder().build();
        request.setEmailAddress(emailAddress);
        request.setSize(keySize);
        request.setFormat(format);
        request.setPublicKey(keyPair.getPublic());
        KeyGenerateResponse response = ClientUtils.bcClientRegister(request);
        if (response.getStatus() == 200) {
            Signature signer = Signature.getInstance("SHA256withRSA", provider);
            signer.initSign(keyPair.getPrivate());
            signer.update(response.getKeyId().getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signer.sign();
            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
            Key key = Key.builder().build();
            key.setKeyId(response.getKeyId());
            key.setSize(keySize);
            key.setFormat(format);
            key.setType(KeyTypeEnum.BC);
            key.setDecentralized(true);
            key.setKeyPassword(signatureBase64);
            key.setPrivateKey(PrivateKeyUtils.convert(keyPair.getPrivate()));
            key.setPublicKey(keyPair.getPublic());
            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key));
        } else {
            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
        }
    }

    public static void yubicoClientGenerate(String _slot, String pin, String _size, String managementKey, String _format, String serialNumber, String emailAddress, String output) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException, InterruptedException {
        int size = Integer.parseInt(_size);
        Slot slot = null;
        for (Slot __slot : Slot.values()) {
            if (__slot.getStringAlias().equalsIgnoreCase(_slot)) {
                slot = __slot;
                break;
            }
        }
        KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
        YubiKeyDevice device = YubicoProviderUtils.lookupDevice(serialNumber);
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            PivSession session = new PivSession(connection);
            session.authenticate(YubicoProviderUtils.hexStringToByteArray(managementKey));
            PublicKey publicKey = null;
            switch (format) {
                case RSA -> {
                    switch (size) {
                        case 1024 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, slot, KeyType.RSA1024);
                        }
                        case 2048 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, slot, KeyType.RSA2048);
                        }
                    }
                }
                case EC -> {
                    switch (size) {
                        case 256 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, slot, KeyType.ECCP256);
                        }
                        case 384 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, slot, KeyType.ECCP384);
                        }
                    }
                }
            }

            YubicoRegisterRequest request = YubicoRegisterRequest.builder()
                    .size(size)
                    .slot(slot.getStringAlias())
                    .serialNumber(serialNumber)
                    .managementKey(managementKey)
                    .emailAddress(emailAddress)
                    .pin(pin)
                    .build();
            request.setFormat(format);
            request.setPublicKey(publicKey);
            KeyGenerateResponse response = ClientUtils.yubicoRegister(request);
            if (response.getStatus() == 200) {
                YubicoPassword yubico = YubicoPassword.builder().build();
                yubico.setSerial(serialNumber);
                yubico.setPin(pin);
                yubico.setPivSlot(slot.getStringAlias());
                yubico.setManagementKey(managementKey);

                String password = RandomStringUtils.secureStrong().nextAlphanumeric(20);
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(password);
                Key key = Key.builder().build();
                key.setKeyId(response.getKeyId());
                key.setKeyPassword(password);
                key.setPublicKey(publicKey);
                key.setPrivateKey(encryptor.encrypt(MAPPER.writeValueAsString(yubico)));
                key.setSize(size);
                key.setFormat(format);
                key.setType(KeyTypeEnum.Yubico);
                key.setDecentralized(false);
                if (output != null && !output.isEmpty()) {
                    FileUtils.write(new File(output), MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key), StandardCharsets.UTF_8);
                } else {
                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key));
                }
            } else {
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(response));
            }
        }
    }

    public static void yubicoServerGenerate(String _slot, String managementKey, String _size, String _format, String serialNumber, String emailAddress) throws IOException, InterruptedException {
        int size = Integer.parseInt(_size);
        KeyFormatEnum format = KeyFormatEnum.valueOf(_format);
        KeyGenerateResponse response = ClientUtils.yubicoGenerate(
                YubicoGenerateRequest.builder()
                        .size(size)
                        .format(format)
                        .serialNumber(serialNumber)
                        .emailAddress(emailAddress)
                        .slot(_slot)
                        .managementKey(managementKey)
                        .build());

        Key key = Key.builder().build();
        key.setKeyId(response.getKeyId());
        key.setKeyPassword(response.getKeyPassword());
        key.setPublicKey(response.getOpenSshPublicKey());
        key.setSize(size);
        key.setFormat(format);
        key.setType(KeyTypeEnum.Yubico);
        key.setDecentralized(false);
        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(key));
    }

}
