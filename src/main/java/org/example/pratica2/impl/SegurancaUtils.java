package org.example.pratica2.impl;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SegurancaUtils {


    //Gera um par de chaves RSA (Pública/Privada) com 2048 bits.

    public static KeyPair gerarParChavesRSA() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }


    //Gera uma chave simétrica AES de 128 bits.
    public static SecretKey gerarChaveAES() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }

    //Gera uma chave simétrica para o HMAC-SHA256. Para validar a integridade do payload cifrado.
    public static SecretKey gerarChaveHMAC() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
        return generator.generateKey();
    }

    /*
      payload é o texto claro
      rsaDestino é a chave pública do destinatário, usada para envelopar as chaves simétricas.
     */
    public static String criarMensagemSegura(String payload, PublicKey rsaDestino) throws Exception {
        SecretKey chaveAES = gerarChaveAES();
        SecretKey chaveHMAC = gerarChaveHMAC();

        byte[] iv = new byte[16]; // Bloco do AES = 16 bytes
        // Deixar o IV aleatório para que textos iguais não gerem o mesmo texto cifrado
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // CBC para o texto cifrado não ter relação clara com o texto original
        aesCipher.init(Cipher.ENCRYPT_MODE, chaveAES, ivSpec);
        byte[] payloadCifrado = aesCipher.doFinal(payload.getBytes());

        // texto cifrado assinado com HMAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(chaveHMAC);
        byte[] hmac = mac.doFinal(payloadCifrado);

        // RSA para proteger as chaves AES e HMAC
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaDestino);
        byte[] aesCifrado = rsaCipher.doFinal(chaveAES.getEncoded());
        byte[] hmacKeyCifrado = rsaCipher.doFinal(chaveHMAC.getEncoded());

        //String formatada e codificada em Base64 pronta para ser enviada via socket.
        return Base64.getEncoder().encodeToString(aesCifrado) + ":" +
                Base64.getEncoder().encodeToString(hmacKeyCifrado) + ":" +
                Base64.getEncoder().encodeToString(iv) + ":" +
                Base64.getEncoder().encodeToString(payloadCifrado) + ":" +
                Base64.getEncoder().encodeToString(hmac);
    }

    /*
      pacote é a string recebida via socket
      rsaPrivada é a chave privada do destinatário para abrir o envelope RSA.
    */
    public static String decriptarEValidarMensagem(String pacote, PrivateKey rsaPrivada) throws Exception {
        String[] partes = pacote.split(":");

        // Se o pacote não tiver 5 partes, é lixo ou ataque de formatação.
        if (partes.length != 5) throw new Exception("Formato de pacote seguro inválido");

        // De Base para byte[]
        byte[] aesCifrado = Base64.getDecoder().decode(partes[0]);
        byte[] hmacKeyCifrado = Base64.getDecoder().decode(partes[1]);
        byte[] iv = Base64.getDecoder().decode(partes[2]);
        byte[] payloadCifrado = Base64.getDecoder().decode(partes[3]);
        byte[] hmacRecebido = Base64.getDecoder().decode(partes[4]);

        // Desempacotar as chaves de sessão (RSA).
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivada);
        SecretKey chaveAES = new SecretKeySpec(rsaCipher.doFinal(aesCifrado), "AES");
        SecretKey chaveHMAC = new SecretKeySpec(rsaCipher.doFinal(hmacKeyCifrado), "HmacSHA256");

        // Validação de Integridade (HMAC).
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(chaveHMAC);
        byte[] hmacCalculado = mac.doFinal(payloadCifrado);
        if (!MessageDigest.isEqual(hmacCalculado, hmacRecebido)) { // Para evitar ataques de Timing (comparação em tempo constante).
            throw new SecurityException("FALHA DE INTEGRIDADE: HMAC corrompido");
        }

        // 3. Decifragem do Payload (AES).
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, chaveAES, new IvParameterSpec(iv));
        return new String(aesCipher.doFinal(payloadCifrado)); // Retorna o texto claro original
    }


    // Transforma uma chave pública RSA para uma string Base64.
    public static String publicKeyToString(PublicKey pub) {
        return Base64.getEncoder().encodeToString(pub.getEncoded());
    }

    // Transforma uma String Base em chave pública RSA
    public static PublicKey stringToPublicKey(String b64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    // Salva a chave pública localmente
    public static void salvarChavePublica(String filename, PublicKey pub) throws IOException {
        try (FileWriter fw = new FileWriter(filename)) {
            fw.write(publicKeyToString(pub));
        }
    }

    // Lê a chave pública armazenada localmente
    public static PublicKey carregarChavePublica(String filename) throws Exception {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            return stringToPublicKey(br.readLine());
        }
    }
}