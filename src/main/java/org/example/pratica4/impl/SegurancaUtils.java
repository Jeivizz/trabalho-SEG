package org.example.pratica4.impl;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SegurancaUtils {
    public static final String DIR_CHAVES    = "keys";
    public static final String RSA_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String AES_TRANSFORM = "AES/CBC/PKCS5Padding";
    public static final String HMAC_ALG      = "HmacSHA256";
    public static final int BLOCO_AES        = 16;

    // Classe de retorno para criar a mensagem segura
    public static class ContextoEnvio {
        public final String pacote;
        public final SecretKey aesKey;
        public final SecretKey hmacKey;
        public ContextoEnvio(String p, SecretKey a, SecretKey h) { pacote = p; aesKey = a; hmacKey = h; }
    }

    // Classe de retorno para criar a mensagem decifrada
    public static class MensagemDecifrada {
        public final String payload;
        public final SecretKey aesKey;
        public final SecretKey hmacKey;
        public MensagemDecifrada(String p, SecretKey a, SecretKey h) { payload = p; aesKey = a; hmacKey = h; }
    }

    // Função para gerar o par de Chaves RSA
    public static KeyPair gerarParChavesRSA() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    // Função para gerar a chave do AES
    public static SecretKey gerarChaveAES() throws Exception {
        KeyGenerator g = KeyGenerator.getInstance("AES");
        g.init(128);
        return g.generateKey();
    }

    // Função para gerar a chave para o HMAC
    public static SecretKey gerarChaveHMAC() throws Exception {
        return KeyGenerator.getInstance(HMAC_ALG).generateKey();
    }

    // Carregar ou Criar o arquivo para fuardar as chaves públicas e privadas
    public static KeyPair carregarOuCriarKeyPair(String nome) throws Exception {
        Path dir  = Paths.get(DIR_CHAVES);
        Path pub  = dir.resolve(nome + ".pub.b64");
        Path priv = dir.resolve(nome + ".priv.b64");

        if (Files.exists(pub) && Files.exists(priv)) {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey p = kf.generatePublic(new X509EncodedKeySpec(
                    Base64.getDecoder().decode(Files.readString(pub).trim())));
            PrivateKey q = kf.generatePrivate(new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(Files.readString(priv).trim())));
            return new KeyPair(p, q);
        }

        KeyPair kp = gerarParChavesRSA();
        Files.createDirectories(dir);
        Files.writeString(pub,  Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
        Files.writeString(priv, Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
        return kp;
    }

    // Carregar chave pública a partir do arquivo
    public static PublicKey carregarPublica(String nome) throws Exception {
        Path pub = Paths.get(DIR_CHAVES).resolve(nome + ".pub.b64");
        return stringToPublicKey(Files.readString(pub).trim());
    }

    // Transformar String (Base64) em Chave Pública
    public static PublicKey stringToPublicKey(String b64) throws Exception {
        byte[] k = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(k));
    }

    // Envelope com AES-CBC, HMAC e RSA-OAEP
    public static ContextoEnvio criarMensagemSegura(String payload, PublicKey rsaDestino) throws Exception {
        SecretKey aesKey  = gerarChaveAES();
        SecretKey hmacKey = gerarChaveHMAC();

        // IV aleatorio pra cada mensagem (CBC exige)
        byte[] iv = new byte[BLOCO_AES];
        new SecureRandom().nextBytes(iv);

        // AES-CBC
        Cipher aes = Cipher.getInstance(AES_TRANSFORM);
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] cifrado = aes.doFinal(payload.getBytes("UTF-8"));

        // HMAC sobre o cifrado (Encrypt-then-MAC)
        Mac mac = Mac.getInstance(HMAC_ALG);
        mac.init(hmacKey);
        byte[] tag = mac.doFinal(cifrado);

        // RSA-OAEP envelopa as duas chaves simetricas
        Cipher rsa = Cipher.getInstance(RSA_TRANSFORM);
        rsa.init(Cipher.ENCRYPT_MODE, rsaDestino);
        byte[] aesCifrada  = rsa.doFinal(aesKey.getEncoded());
        byte[] hmacCifrada = rsa.doFinal(hmacKey.getEncoded());

        // Transforma informações em Base64 para ser enviado
        Base64.Encoder b64 = Base64.getEncoder();
        String pacote = b64.encodeToString(aesCifrada)  + ":" +
                b64.encodeToString(hmacCifrada) + ":" +
                b64.encodeToString(iv)          + ":" +
                b64.encodeToString(cifrado)     + ":" +
                b64.encodeToString(tag);
        return new ContextoEnvio(pacote, aesKey, hmacKey);
    }

    // Reverter o envelope para obter o texto original e validar
    public static MensagemDecifrada decriptarEValidarMensagem(String pacote, PrivateKey rsaPrivada) throws Exception {
        String[] partes = pacote.split(":");
        if (partes.length != 5) throw new SecurityException("Pacote mal formado"); // Erro de formatação

        // De Base64 para byte[]
        Base64.Decoder b64 = Base64.getDecoder();
        byte[] aesCifrada  = b64.decode(partes[0]);
        byte[] hmacCifrada = b64.decode(partes[1]);
        byte[] iv          = b64.decode(partes[2]);
        byte[] cifrado     = b64.decode(partes[3]);
        byte[] tagRecebido = b64.decode(partes[4]);

        // abre o envelope RSA
        Cipher rsa = Cipher.getInstance(RSA_TRANSFORM);
        rsa.init(Cipher.DECRYPT_MODE, rsaPrivada);
        SecretKey aesKey  = new SecretKeySpec(rsa.doFinal(aesCifrada),  "AES");
        SecretKey hmacKey = new SecretKeySpec(rsa.doFinal(hmacCifrada), HMAC_ALG);

        // valida HMAC ANTES de decifrar
        Mac mac = Mac.getInstance(HMAC_ALG);
        mac.init(hmacKey);
        byte[] tagCalc = mac.doFinal(cifrado);
        if (!MessageDigest.isEqual(tagCalc, tagRecebido)) {
            throw new SecurityException("HMAC invalido");
        }

        // decifra AES-CBC
        Cipher aes = Cipher.getInstance(AES_TRANSFORM);
        aes.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        String payload = new String(aes.doFinal(cifrado), "UTF-8");

        return new MensagemDecifrada(payload, aesKey, hmacKey);
    }

    // Resposta segura feita com AES e HMAC, utilizando as chaves geradas antes
    public static String criarRespostaSegura(String payload, SecretKey aesKey, SecretKey hmacKey) throws Exception {
        byte[] iv = new byte[BLOCO_AES];
        new SecureRandom().nextBytes(iv);

        Cipher aes = Cipher.getInstance(AES_TRANSFORM);
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] cifrado = aes.doFinal(payload.getBytes("UTF-8"));

        Mac mac = Mac.getInstance(HMAC_ALG);
        mac.init(hmacKey);
        byte[] tag = mac.doFinal(cifrado);

        // Passar para Base64 para que seja enviado
        Base64.Encoder b64 = Base64.getEncoder();
        return b64.encodeToString(iv)      + ":" +
                b64.encodeToString(cifrado) + ":" +
                b64.encodeToString(tag);
    }

    // Desfazer o envelope da resposta segura (AES - HMAC)
    public static String decifrarResposta(String pacote, SecretKey aesKey, SecretKey hmacKey) throws Exception {
        String[] partes = pacote.split(":");
        if (partes.length != 3) throw new SecurityException("Resposta mal formada");

        // De Base64 para byte[]
        Base64.Decoder b64 = Base64.getDecoder();
        byte[] iv          = b64.decode(partes[0]);
        byte[] cifrado     = b64.decode(partes[1]);
        byte[] tagRecebido = b64.decode(partes[2]);

        Mac mac = Mac.getInstance(HMAC_ALG);
        mac.init(hmacKey);
        byte[] tagCalc = mac.doFinal(cifrado);
        if (!MessageDigest.isEqual(tagCalc, tagRecebido)) {
            throw new SecurityException("HMAC invalido na resposta");
        }

        Cipher aes = Cipher.getInstance(AES_TRANSFORM);
        aes.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return new String(aes.doFinal(cifrado), "UTF-8");
    }
}