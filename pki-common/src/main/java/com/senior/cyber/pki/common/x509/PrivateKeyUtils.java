package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;

public class PrivateKeyUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static String signText(PrivateKey privateKey, String text) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = null;
        if (privateKey instanceof RSAPrivateKey) {
            signature = Signature.getInstance("SHA256withRSA");
        } else if (privateKey instanceof ECPrivateKey) {
            signature = Signature.getInstance("SHA256withECDSA");
        } else {
            throw new IllegalArgumentException(privateKey.getClass().getName() + " is not supported");
        }
        signature.initSign(privateKey, new SecureRandom());
        signature.update(text.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signature.sign()) + "." + text;
    }

    public static String decryptText(PrivateKey privateKey, String text) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        if (privateKey instanceof RSAPrivateKey) {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] textData = cipher.doFinal(Base64.getDecoder().decode(text));
            return new String(textData, StandardCharsets.UTF_8);
        } else if (privateKey instanceof ECPrivateKey) {
            int dotIndex = text.indexOf('.');
            byte[] iv = Base64.getDecoder().decode(text.substring(0, dotIndex));
            byte[] derivation = iv.clone();
            byte[] encoding = iv.clone();
            int length = iv.length;
            Cipher cipher = Cipher.getInstance("ECIESwithSHA256andAES-CBC", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, new IESParameterSpec(derivation, encoding, length * 8, length * 8, iv, false));
            byte[] textData = cipher.doFinal(Base64.getDecoder().decode(text.substring(dotIndex + 1)));
            return new String(textData, StandardCharsets.UTF_8);
        } else {
            throw new IllegalArgumentException(privateKey.getClass().getName() + " is not supported");
        }
    }

    public static PrivateKey convert(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object objectHolder = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (objectHolder instanceof PKCS8EncryptedPrivateKeyInfo holder) {
                throw new IllegalArgumentException("Encrypted private key is not supported");
            } else if (objectHolder instanceof PEMKeyPair holder) {
                return converter.getPrivateKey(holder.getPrivateKeyInfo());
            } else if (objectHolder instanceof PrivateKeyInfo holder) {
                return converter.getPrivateKey(holder);
            } else {
                throw new UnsupportedOperationException(objectHolder.getClass().getName());
            }
        } catch (IOException e) {
            return null;
        }
    }

    public static PrivateKey convert(String value, String password) throws OperatorCreationException {
        InputDecryptorProvider _decryptor = null;
        JceOpenSSLPKCS8DecryptorProviderBuilder decryptorBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
        decryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        _decryptor = decryptorBuilder.build(password.toCharArray());

        if (value == null || value.isEmpty()) {
            return null;
        }
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object objectHolder = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (objectHolder instanceof PKCS8EncryptedPrivateKeyInfo holder) {
                PrivateKeyInfo info = holder.decryptPrivateKeyInfo(_decryptor);
                return converter.getPrivateKey(info);
            } else if (objectHolder instanceof PEMKeyPair holder) {
                return converter.getPrivateKey(holder.getPrivateKeyInfo());
            } else if (objectHolder instanceof PrivateKeyInfo holder) {
                return converter.getPrivateKey(holder);
            } else {
                throw new UnsupportedOperationException(objectHolder.getClass().getName());
            }
        } catch (IOException | PKCSException e) {
            return null;
        }
    }

    public static String convert(PrivateKey value) {
        if (value == null) {
            return null;
        }
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(value);
        } catch (IOException e) {
            return null;
        }
        return pem.toString();
    }

    public static String convert(PrivateKey value, String password) throws OperatorCreationException {
        OutputEncryptor _encryptor = null;
        JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC);
        encryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        encryptorBuilder.setRandom(new SecureRandom());
        encryptorBuilder.setPassword(password.toCharArray());
        encryptorBuilder.setIterationCount(10000);
        _encryptor = encryptorBuilder.build();

        if (value == null) {
            return null;
        }
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(new JcaPKCS8Generator(value, _encryptor));
        } catch (IOException e) {
            return null;
        }
        return pem.toString();
    }

}
