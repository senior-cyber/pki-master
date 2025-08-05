//package com.senior.cyber.pki.service;
//
//import com.senior.cyber.pki.service.util.YubicoProviderUtils;
//import com.yubico.yubikit.core.YubiKeyDevice;
//import com.yubico.yubikit.core.application.CommandException;
//import com.yubico.yubikit.core.smartcard.SmartCardConnection;
//import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
//import com.yubico.yubikit.management.DeviceInfo;
//import com.yubico.yubikit.management.ManagementSession;
//import com.yubico.yubikit.oath.OathSession;
//
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//
//public class Program {
//
//    public static void main(String[] args) throws IOException, CommandException {
//        YubiKeyDevice device = YubicoProviderUtils.lookupDevice("34247908");
//
////        if (device.supportsConnection(SmartCardConnection.class)) {
////            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
////                PivSession session = new PivSession(connection);
////            }
////        }
////
////        if (device.supportsConnection(SmartCardConnection.class)) {
////            try (FidoConnection connection = device.openConnection(FidoConnection.class)) {
////                Ctap2Session session = new Ctap2Session(connection);
////            }
////        }
////
//        if (device.supportsConnection(SmartCardConnection.class)) {
//            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
//                OathSession session = new OathSession(connection);
////                session.setAccessKey("".getBytes(StandardCharsets.UTF_8));
////                session.setPassword("".toCharArray());
//            }
//        }
//
//        if (device.supportsConnection(SmartCardConnection.class)) {
//            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
//                ManagementSession session = new ManagementSession(connection);
//                //DeviceInfo deviceInfo = session.getDeviceInfo();
//                System.out.println("");
//            }
//        }
//
//        if (device.supportsConnection(SmartCardConnection.class)) {
//            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
//                SecurityDomainSession session = new SecurityDomainSession(connection);
//            }
//        }
//
////        if (device.supportsConnection(OtpConnection.class)) {
////            try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
////                YubiOtpSession session = new YubiOtpSession(connection);
//////                ConfigurationState state = session.getConfigurationState();
//////            String configuredSlots = " ";
//////            if (state.isConfigured(Slot.ONE)) {
//////                configuredSlots += "SLOT1 ";
//////            }
//////            if (state.isConfigured(Slot.TWO)) {
//////                configuredSlots += "SLOT2";
//////            }
//////            System.out.println(configuredSlots);
////            }
////        }
//
////        if (device.supportsConnection(OtpConnection.class)) {
////            try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
////                YubiOtpSession session = new YubiOtpSession(connection);
////                ConfigurationState state = session.getConfigurationState();
//////            String configuredSlots = " ";
//////            if (state.isConfigured(Slot.ONE)) {
//////                configuredSlots += "SLOT1 ";
//////            }
//////            if (state.isConfigured(Slot.TWO)) {
//////                configuredSlots += "SLOT2";
//////            }
//////            System.out.println(configuredSlots);
////            }
////        }
//
////        if (device.supportsConnection(FidoConnection.class)) {
////            try (FidoConnection connection = device.openConnection(FidoConnection.class)) {
////                FidoProtocol session = new FidoProtocol(connection);
////                Ctap2Session ctap2Session = new Ctap2Session(connection);
////                CommandState state = new CommandState();
////                ctap2Session.reset(state);   // CommandState can be null for blocking call
////            }
////        }
//    }
//
//}
