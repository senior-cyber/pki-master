package com.senior.cyber.pki.service;

import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.otp.Modhex;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.oath.OathSession;
import com.yubico.yubikit.yubiotp.Slot;
import com.yubico.yubikit.yubiotp.YubiOtpSession;
import com.yubico.yubikit.yubiotp.YubiOtpSlotConfiguration;

import java.io.Console;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

public class Program {

    public static void main(String[] args) throws IOException, CommandException, NoSuchAlgorithmException {

//        YubiKitManager manager = new YubiKitManager();
//        for (Map.Entry<YubiKeyDevice, DeviceInfo> p : manager.listAllDevices().entrySet()) {
//            YubiKeyDevice device = p.getKey();
//            DeviceInfo info = p.getValue();
//            System.out.println(info.getSerialNumber());
//        }

        YubiKeyDevice device = YubicoProviderUtils.lookupDevice("34247908");

//        if (device.supportsConnection(SmartCardConnection.class)) {
//            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
//                PivSession session = new PivSession(connection);
//            }
//        }
//
//        if (device.supportsConnection(SmartCardConnection.class)) {
//            try (FidoConnection connection = device.openConnection(FidoConnection.class)) {
//                Ctap2Session session = new Ctap2Session(connection);
//            }
//        }
//
        if (device.supportsConnection(SmartCardConnection.class)) {
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                OathSession session = new OathSession(connection);
//                session.setAccessKey("".getBytes(StandardCharsets.UTF_8));
//                session.setPassword("".toCharArray());
            }
        }

        if (device.supportsConnection(SmartCardConnection.class)) {
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                ManagementSession session = new ManagementSession(connection);
                //DeviceInfo deviceInfo = session.getDeviceInfo();
                System.out.println("");
            }
        }

        if (device.supportsConnection(SmartCardConnection.class)) {
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                SecurityDomainSession session = new SecurityDomainSession(connection);
            }
        }

        if (device.supportsConnection(OtpConnection.class)) {
            try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
                YubiOtpSession session = new YubiOtpSession(connection);

                // 1) Serial → public ID (modhex), like --serial-public-id
                int serial = session.getSerialNumber(); // may throw if serial isn't API-visible. :contentReference[oaicite:3]{index=3}
                // ykman’s --serial-public-id uses the device serial as the public ID in modhex.
                // We encode the serial as 6 bytes big-endian and modhex-encode → 12 chars.
                byte[] serial6 = new byte[6];
                for (int i = 5; i >= 0; i--) {
                    serial6[i] = (byte) (serial & 0xFF);
                    serial >>>= 8;
                }
                String publicIdModhex = Modhex.encode(serial6); // com.yubico.yubikit.core.otp.Modhex :contentReference[oaicite:4]{index=4}


                // 2) Generate private ID (6 bytes) and secret key (16 bytes), like -g and -G
                SecureRandom rng = SecureRandom.getInstanceStrong();
                byte[] privateId = new byte[6];
                byte[] secretKey = new byte[16];
                rng.nextBytes(privateId);
                rng.nextBytes(secretKey);

                String privateIdHex = HexFormat.of().formatHex(privateId);
                String secretKeyHex = HexFormat.of().formatHex(secretKey);

                System.out.println("Using YubiKey serial as public ID: " + publicIdModhex);
                System.out.println("Using a randomly generated private ID: " + privateIdHex);
                System.out.println("Using a randomly generated secret key: " + secretKeyHex);

                // 4) Build and write configuration to SLOT 1
                // publicId (modhex) -> bytes; privateId/key are raw bytes.
                byte[] publicIdBytes = Modhex.decode(publicIdModhex);

                YubiOtpSlotConfiguration cfg = new YubiOtpSlotConfiguration(publicIdBytes, privateId, secretKey);
                // With default flags this mimics "ykman otp yubiotp 1 ..." behavior. :contentReference[oaicite:5]{index=5}

                session.putConfiguration(Slot.ONE, cfg, null, null); // write, no access code. :contentReference[oaicite:6]{index=6}
                System.out.println("Slot 1 programmed.");
            }
        }

//        if (device.supportsConnection(OtpConnection.class)) {
//            try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
//                YubiOtpSession session = new YubiOtpSession(connection);
//                ConfigurationState state = session.getConfigurationState();
////            String configuredSlots = " ";
////            if (state.isConfigured(Slot.ONE)) {
////                configuredSlots += "SLOT1 ";
////            }
////            if (state.isConfigured(Slot.TWO)) {
////                configuredSlots += "SLOT2";
////            }
////            System.out.println(configuredSlots);
//            }
//        }

//        if (device.supportsConnection(FidoConnection.class)) {
//            try (FidoConnection connection = device.openConnection(FidoConnection.class)) {
//                FidoProtocol session = new FidoProtocol(connection);
//                Ctap2Session ctap2Session = new Ctap2Session(connection);
//                CommandState state = new CommandState();
//                ctap2Session.reset(state);   // CommandState can be null for blocking call
//            }
//        }
    }

}
