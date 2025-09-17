package com.senior.cyber.pki.common.x509;

import com.yubico.yubikit.piv.jca.PivProvider;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Base64;

@Slf4j
public class PublicKeyUtils {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    public static boolean verifyText(PublicKey publicKey, String text) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = null;
        if (publicKey instanceof RSAKey) {
            signature = Signature.getInstance("SHA256withRSA");
        } else if (publicKey instanceof ECKey) {
            signature = Signature.getInstance("SHA256withECDSA");
        } else {
            throw new IllegalArgumentException(publicKey.getClass().getName() + " is not supported");
        }
        signature.initVerify(publicKey);
        int dotIndex = text.indexOf('.');
        signature.update(text.substring(dotIndex + 1).getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getDecoder().decode(text.substring(0, dotIndex)));
    }

    public static String encryptText(Provider provider, PublicKey publicKey, String text) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (publicKey instanceof RSAKey) {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherData = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(cipherData);
        } else if (publicKey instanceof ECKey) {
            if (provider instanceof BouncyCastleProvider) {
                int length = 16;
                byte[] iv = RANDOM.generateSeed(length);
                byte[] derivation = iv.clone();
                byte[] encoding = iv.clone();
                Cipher cipher = Cipher.getInstance("ECIESwithSHA256andAES-CBC");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, new IESParameterSpec(derivation, encoding, length * 8, length * 8, iv, false));
                byte[] cipherData = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(iv) + "." + Base64.getEncoder().encodeToString(cipherData);
            } else if (provider instanceof PivProvider) {
                throw new IllegalArgumentException(publicKey.getClass().getName() + " is not supported");
            } else {
                throw new IllegalArgumentException(provider.getClass().getName() + " is not supported");
            }
        } else {
            throw new IllegalArgumentException(publicKey.getClass().getName() + " is not supported");
        }
    }

    public static String convert(PublicKey value) {
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(value);
        } catch (IOException e) {
            return null;
        }
        return pem.toString();
    }

    public static PublicKey convert(String value) {
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object object = parser.readObject();
            if (object instanceof X509CertificateHolder holder) {
                JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
                converter.setProvider(PROVIDER);
                X509Certificate certificate = converter.getCertificate(holder);
                return certificate.getPublicKey();
            } else if (object instanceof SubjectPublicKeyInfo holder) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                converter.setProvider(PROVIDER);
                return converter.getPublicKey(holder);
            } else {
                throw new java.lang.UnsupportedOperationException(object.getClass().getName());
            }
        } catch (CertificateException | IOException e) {
            return null;
        }
    }

}
