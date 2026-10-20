package org.example.pratica1;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

public final class CriptoUtil {

    // Tamanhos fixos do protocolo
    public static final int TAM_DATAGRAMA = 4096; // buffer UDP (RSA-2048 cabe)
    public static final int TAM_CHAVE_AES = 32;   // AES-256
    public static final int TAM_CHAVE_MAC = 32;   // HMAC-SHA256
    public static final int TAM_IV = 16;          // IV do CBC

    private static final SecureRandom RNG = new SecureRandom();

    // Parâmetros do RSA-OAEP com SHA-256 
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private CriptoUtil() {
    }

    // ASSIMÉTRICO (RSA) — usado só no handshake 

    public static KeyPair gerarParRsa() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048); // 2048 bits
        return g.generateKeyPair();
    }

    public static byte[] rsaCifrar(PublicKey chave, byte[] dados) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(Cipher.ENCRYPT_MODE, chave, OAEP);
        return c.doFinal(dados);
    }

    public static byte[] rsaDecifrar(PrivateKey chave, byte[] dados) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(Cipher.DECRYPT_MODE, chave, OAEP);
        return c.doFinal(dados);
    }

    // SIMÉTRICO (AES-256/CBC) — usado em todas as mensagens 

    public static byte[] aesCifrar(byte[] chave, byte[] iv, byte[] claro) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chave, "AES"), new IvParameterSpec(iv));
        return c.doFinal(claro);
    }

    public static byte[] aesDecifrar(byte[] chave, byte[] iv, byte[] cifrado) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chave, "AES"), new IvParameterSpec(iv));
        return c.doFinal(cifrado);
    }

    //  INTEGRIDADE (HMAC-SHA256) — garante autenticidade e detecção de adulteração 

    public static byte[] hmac(byte[] chave, byte[] dados) throws GeneralSecurityException {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(chave, "HmacSHA256"));
        return m.doFinal(dados);
    }

    // Comparação em TEMPO CONSTANTE: evita timing attack
    public static boolean iguais(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
 

    public static byte[] aleatorios(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b); // SecureRandom, não Random
        return b;
    }

    public static String b64(byte[] dados) {
        return Base64.getEncoder().encodeToString(dados);
    }

    public static byte[] deb64(String texto) {
        return Base64.getDecoder().decode(texto);
    }

    public static String hex(byte[] dados) {
        StringBuilder sb = new StringBuilder();
        for (byte b : dados) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Impressão digital SHA-256 da chave pública mostra no log que o clientee
    // recebeu a chave certa; ajuda a argumentar contra MITM
    public static String impressaoDigital(PublicKey chave) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(chave.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i++) {
                sb.append(String.format("%02X", h[i]));
                if (i < 15) {
                    sb.append(':');
                }
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String abreviar(String texto, int n) {
        return texto.length() <= n ? texto : texto.substring(0, n) + "...";
    }
}