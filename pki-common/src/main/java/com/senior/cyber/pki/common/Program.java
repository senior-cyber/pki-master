package com.senior.cyber.pki.common;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.InvalidPinException;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class Program {

    public static void main(String[] args) throws ApduException, IOException, InvalidPinException, NoSuchAlgorithmException {
        System.out.println("Hello World");

        YPi

        YubiKeyDevice device = null;// ... ;

        device.requestConnection(SmartCardConnection::class.java) {
            PivSession pivSession = new PivSession(it.value);
            // use pivSession
        }

        PivSession piv = new PivSession(smartCardConnection);
// Verify the PIN:
        char[] pin = "123456".toCharArray();
        piv.verifyPin(pin);

        String message = "Hello World";

// Sign a message using a private key on the YubiKey:
        byte[] signature = piv.sign(
                Slot.SIGNATURE,
                KeyType.ECCP256,
                message,
                Signature.getInstance("SHA256withECDSA")
        );
    }

}
