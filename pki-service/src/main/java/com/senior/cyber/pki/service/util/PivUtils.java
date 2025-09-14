package com.senior.cyber.pki.service.util;

import com.senior.cyber.pki.common.dto.YubicoPassword;
import com.senior.cyber.pki.common.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Map;

public class PivUtils {

    public static PrivateKey lookupPrivateKey(
            Map<String, PivProvider> providers,
            Map<String, SmartCardConnection> connections,
            Map<String, PivSession> sessions,
            Map<String, Slot> slots,
            Map<String, String> serials,
            Map<String, KeyStore> keys,
            String keyId,
            YubicoPassword yubico) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        serials.put(keyId, yubico.getSerial());
        KeyStore ks = null;
        if (!connections.containsKey(yubico.getSerial())) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(yubico.getSerial());
            SmartCardConnection connection = device.openConnection(SmartCardConnection.class);
            connections.put(yubico.getSerial(), connection);
            PivSession session = new PivSession(connection);
            session.authenticate(YubicoProviderUtils.hexStringToByteArray(yubico.getManagementKey()));
            sessions.put(yubico.getSerial(), session);
            PivProvider provider = new PivProvider(session);
            providers.put(yubico.getSerial(), provider);
            ks = YubicoProviderUtils.lookupKeyStore(provider);
            keys.put(yubico.getSerial(), ks);
        } else {
            ks = keys.get(yubico.getSerial());
        }
        Slot slot = null;
        for (Slot s : Slot.values()) {
            if (s.getStringAlias().equalsIgnoreCase(yubico.getPivSlot())) {
                slot = s;
                break;
            }
        }
        slots.put(yubico.getSerial(), slot);
        return YubicoProviderUtils.lookupPrivateKey(ks, slot, yubico.getPin());
    }

}
