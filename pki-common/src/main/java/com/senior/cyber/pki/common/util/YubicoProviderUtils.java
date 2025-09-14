package com.senior.cyber.pki.common.util;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.piv.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

public class YubicoProviderUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(YubicoProviderUtils.class);

    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return result;
    }

    public static YubiKeyDevice lookupDevice(String serialNumber) {
        YubiKitManager manager = new YubiKitManager();
        for (Map.Entry<YubiKeyDevice, DeviceInfo> p : manager.listAllDevices().entrySet()) {
            YubiKeyDevice device = p.getKey();
            DeviceInfo info = p.getValue();
            if (String.valueOf(info.getSerialNumber()).equals(serialNumber)) {
                return device;
            }
        }
        return null;
    }

    public static PublicKey generateKey(PivSession session, Slot pivSlot, KeyType keyType) {
        try {
            PublicKeyValues publicKeyValues = session.generateKeyValues(pivSlot, keyType, PinPolicy.NEVER, TouchPolicy.NEVER);
            return publicKeyValues.toPublicKey();
        } catch (IOException | ApduException | BadResponseException | NoSuchAlgorithmException |
                 InvalidKeySpecException e) {
            LOGGER.info("lookupPublicKey [{}] [{}]", e.getClass().getSimpleName(), e.getMessage());
        }
        return null;
    }

    public static KeyStore lookupKeyStore(Provider provider) {
        try {
            KeyStore ks = KeyStore.getInstance("YKPiv", provider);
            ks.load(null);  // PIN
            return ks;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            LOGGER.info("lookupPublicKey [{}] [{}]", e.getClass().getSimpleName(), e.getMessage());
        }
        return null;
    }

    public static PrivateKey lookupPrivateKey(KeyStore ks, Slot slot, String pin) {
        try {
            return (PrivateKey) ks.getKey(slot.getStringAlias(), pin.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            LOGGER.info("lookupPublicKey [{}] [{}]", e.getClass().getSimpleName(), e.getMessage());
        }
        return null;
    }

    public static PublicKey lookupPublicKey(PivSession session, Slot slot) {
        if (session.supports(PivSession.FEATURE_METADATA)) {
            try {
                SlotMetadata meta = session.getSlotMetadata(slot);
                return meta.getPublicKeyValues().toPublicKey();
            } catch (ApduException | IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                LOGGER.info("lookupPublicKey [{}] [{}]", e.getClass().getSimpleName(), e.getMessage());
            }
        }

        try {
            X509Certificate certificate = session.getCertificate(slot);
            return certificate.getPublicKey();
        } catch (BadResponseException | IOException | ApduException e) {
            LOGGER.info("lookupPublicKey [{}] [{}]", e.getClass().getSimpleName(), e.getMessage());
        }

        if (session.supports(PivSession.FEATURE_ATTESTATION)) {
            try {
                X509Certificate certificate = session.attestKey(slot);
                return certificate.getPublicKey();
            } catch (BadResponseException | IOException | ApduException e) {
                LOGGER.info("lookupPublicKey [{}] [{}]", e.getClass().getSimpleName(), e.getMessage());
            }
        }

        return null;
    }

}
