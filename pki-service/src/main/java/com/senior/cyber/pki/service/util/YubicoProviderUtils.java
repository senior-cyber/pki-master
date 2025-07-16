package com.senior.cyber.pki.service.util;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.piv.*;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

public class YubicoProviderUtils {

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
        PublicKeyValues publicKeyValues = null;
        try {
            publicKeyValues = session.generateKeyValues(pivSlot, keyType, PinPolicy.NEVER, TouchPolicy.NEVER);
        } catch (IOException | ApduException | BadResponseException e) {
            return null;
        }
        try {
            return publicKeyValues.toPublicKey();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }
    }

    public static KeyStore lookupKeyStore(Provider provider) {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("YKPiv", provider);
        } catch (KeyStoreException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }
        try {
            ks.load(null);  // PIN
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }
        return ks;
    }

    public static PrivateKey lookupPrivateKey(KeyStore ks, Slot slot, String pin) {
        try {
            return (PrivateKey) ks.getKey(slot.getStringAlias(), pin.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            return null;
        }
    }

}
