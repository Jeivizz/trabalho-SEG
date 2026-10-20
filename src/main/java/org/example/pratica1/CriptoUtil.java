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

// Funções criptográficas usadas pelo projeto. Só usa a biblioteca padrão do
// Java (JCA/JCE): nada de dependências externas.
//
// CRIPTOGRAFIA HÍBRIDA:
//   - ASSIMÉTRICA (RSA-2048 + OAEP/SHA-256): usada UMA vez, no handshake, só
//     para transportar com segurança as chaves simétricas até o servidor.
//     É lenta e limitada em tamanho, por isso não cifra as mensagens.
//   - SIMÉTRICA (AES-256-CBC): cifra todas as mensagens depois do handshake
//     (rápida e sem limite prático de tamanho). Garante CONFIDENCIALIDADE.
//   - HMAC-SHA256 (chave própria, diferente da AES): garante INTEGRIDADE e
//     AUTENTICIDADE. Quem não tem a chave não consegue gerar um HMAC válido.
public final class CriptoUtil {

    public static final int TAM_DATAGRAMA = 4096; // buffer de recepção UDP
    public static final int TAM_CHAVE_AES = 32;   // 256 bits
    public static final int TAM_CHAVE_MAC = 32;   // 256 bits
    public static final int TAM_IV = 16;          // bloco do AES

    private static final SecureRandom RNG = new SecureRandom();

    // OAEP com SHA-256 também no MGF1 (por padrão o Java usaria SHA-1 no MGF1).
    // Servidor e clientes usam exatamente a mesma especificação.
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private CriptoUtil() {
    }

    // ---------------- RSA ----------------

    public static KeyPair gerarParRsa() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    // Com RSA-2048 + OAEP-SHA256 cabem no máximo 190 bytes por operação.
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

    // ---------------- AES ----------------

    // IV (vetor de inicialização) ALEATÓRIO e diferente a cada mensagem:
    // assim a mesma mensagem cifrada duas vezes gera textos cifrados distintos.
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

    // ---------------- HMAC ----------------

    public static byte[] hmac(byte[] chave, byte[] dados) throws GeneralSecurityException {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(chave, "HmacSHA256"));
        return m.doFinal(dados);
    }

    // Comparação em TEMPO CONSTANTE: um equals() comum retorna ao achar o primeiro
    // byte diferente, e o tempo gasto poderia vazar informação sobre o HMAC correto.
    public static boolean iguais(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    // ---------------- utilidades ----------------

    public static byte[] aleatorios(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public static String b64(byte[] dados) {
        return Base64.getEncoder().encodeToString(dados);
    }

    // Lança IllegalArgumentException se não for Base64 válido.
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

    // "Impressão digital" da chave pública (SHA-256), para o usuário conferir
    // por outro canal que a chave recebida é mesmo a do servidor.
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
            throw new IllegalStateException(e); // SHA-256 sempre existe no Java
        }
    }

    public static String abreviar(String texto, int n) {
        return texto.length() <= n ? texto : texto.substring(0, n) + "...";
    }
}
