//package com.senior.cyber.pki.service.util;
//
//import com.senior.cyber.pki.common.x509.CertificateUtils;
//import org.apache.commons.exec.CommandLine;
//import org.apache.commons.exec.DefaultExecutor;
//import org.apache.commons.exec.ExecuteWatchdog;
//import org.apache.commons.exec.PumpStreamHandler;
//import org.apache.commons.io.FileUtils;
//
//import java.io.ByteArrayOutputStream;
//import java.io.File;
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//import java.security.*;
//import java.security.cert.CertificateException;
//import java.security.cert.X509Certificate;
//import java.time.Duration;
//import java.util.ArrayList;
//import java.util.List;
//
//public class Pkcs11HsmProviderUtils {
//
//    public static Provider lookProvider(String usbSlot) {
//        File pkcs11Conf = new File(FileUtils.getTempDirectory(), System.currentTimeMillis() + "-pkcs11.conf");
//        try {
//            List<String> lines = new ArrayList<>();
//            lines.add("name = YubiKey");
//            lines.add("library = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so");
//            lines.add("slot = " + usbSlot);
//
//            FileUtils.writeLines(pkcs11Conf, StandardCharsets.UTF_8.name(), lines);
//            return Security.getProvider("SunPKCS11").configure(pkcs11Conf.getAbsolutePath());
//        } catch (IOException e) {
//            FileUtils.deleteQuietly(pkcs11Conf);
//            throw new RuntimeException(e);
//        } finally {
//            FileUtils.deleteQuietly(pkcs11Conf);
//        }
//    }
//
//    public static KeyStore lookupKeyStore(Provider provider, String pin) {
//        try {
//            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
//            ks.load(null, pin.toCharArray());
//            return ks;
//        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    public static PrivateKey lookupPrivateKey(KeyStore keyStore, YubicoPivSlotEnum pivSlot, String password) {
//        try {
//            return (PrivateKey) keyStore.getKey(pivSlot.getAlias(), password == null ? null : password.toCharArray());
//        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    public static X509Certificate lookupCertificate(KeyStore keyStore, YubicoPivSlotEnum pivSlot) {
//        try {
//            return (X509Certificate) keyStore.getCertificate(pivSlot.getAlias());
//        } catch (KeyStoreException e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    public static void importCertificate(X509Certificate certificate, YubicoPivSlotEnum pivSlot, String pin, String managementKey) {
//        File ca = new File(FileUtils.getTempDirectory(), System.currentTimeMillis() + "-ca.crt");
//        try {
//            FileUtils.writeStringToFile(ca, CertificateUtils.convert(certificate), StandardCharsets.UTF_8);
//            CommandLine cmd = new CommandLine("/usr/local/bin/yubico-piv-tool");
//            cmd.addArgument("-a");
//            cmd.addArgument("verify-pin");
//            cmd.addArgument("-P");
//            cmd.addArgument(pin);
//            cmd.addArgument("-a");
//            cmd.addArgument("import-certificate");
//            cmd.addArgument("-s");
//            cmd.addArgument(pivSlot.getSlotName());
//            cmd.addArgument("-i");
//            cmd.addArgument(ca.getAbsolutePath());
//            cmd.addArgument("-k" + managementKey);
//
//            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
//            PumpStreamHandler streams = new PumpStreamHandler(stdout, null);
//
//            ExecuteWatchdog watchdog = ExecuteWatchdog.builder()
//                    .setTimeout(Duration.ofMinutes(1))
//                    .get();
//
//            DefaultExecutor exec = DefaultExecutor.builder()
//                    .get();
//            exec.setWatchdog(watchdog);
//            exec.setStreamHandler(streams);
//            exec.setExitValue(0);
//
//            exec.execute(cmd);
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        } finally {
//            FileUtils.deleteQuietly(ca);
//        }
//    }
//
//}
