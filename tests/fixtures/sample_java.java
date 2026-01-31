/**
 * Sample Java file with cryptographic patterns for testing.
 */
package com.example.crypto;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class CryptoExample {

    // CRITICAL - RSA key generation
    public void generateRSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }

    // CRITICAL - EC key generation
    public void generateECKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
    }

    // HIGH - MD5 usage
    public byte[] md5Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    // HIGH - SHA-1 usage
    public byte[] sha1Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    // HIGH - DES encryption
    public void useDES() throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
    }

    // MEDIUM - SHA-256 usage
    public byte[] sha256Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    // LOW - AES-256
    public void useAES256() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
    }
}
