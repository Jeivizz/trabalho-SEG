package org.example.pratica3;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;


public class Seguranca {
    private final KeyPair parChaves;
    private final SecureRandom aleatorio = new SecureRandom();

    public Seguranca() {
        try {
            KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
            gerador.initialize(2048);
            parChaves = gerador.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Nao foi possivel gerar as chaves RSA", e);
        }
    }

    // Usado pelo destinatário para enviar sua pubkey ao remetente no início da conexão
    public PublicKey getChavePublica() {
        return parChaves.getPublic();
    }

    // Protege uma Mensagem para um destinatário específico a pubkey DELE
    public PacoteSeguro proteger(Mensagem mensagem, PublicKey chavePublicaDestino)
            throws GeneralSecurityException, IOException {
        //  Gera chaves simétricas efêmeras e IV
        byte[] chaveAes = new byte[32];
        byte[] chaveHmac = new byte[32];
        byte[] iv = new byte[16];
        aleatorio.nextBytes(chaveAes);
        aleatorio.nextBytes(chaveHmac);
        aleatorio.nextBytes(iv);

        //  Serializa a Mensagem e cifra em AES-CBC
        byte[] dados = serializar(mensagem);
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chaveAes, "AES"), new IvParameterSpec(iv));
        byte[] cifrado = aes.doFinal(dados);

        //  HMAC sobre (iv || cifrado) — Encrypt-then-MAC
        byte[] autenticador = calcularHmac(chaveHmac, iv, cifrado);

        //  Cifra as chaves simétricas com a pubkey RSA do DESTINO
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, chavePublicaDestino);
        byte[] chaveAesCifrada = rsa.doFinal(chaveAes);
        rsa.init(Cipher.ENCRYPT_MODE, chavePublicaDestino);
        byte[] chaveHmacCifrada = rsa.doFinal(chaveHmac);

        // Envelope final
        return new PacoteSeguro(chaveAesCifrada, chaveHmacCifrada, iv, cifrado, autenticador);
    }

    // Abre um PacoteSeguro recebido: decifra chaves com a privada RSA,
    // valida HMAC e só então decifra o conteúdo com AES
    public Mensagem abrir(PacoteSeguro pacote) throws GeneralSecurityException, IOException, ClassNotFoundException {
        //  Recupera as chaves simétricas com a chave privada RSA DESTE nó
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.DECRYPT_MODE, parChaves.getPrivate());
        byte[] chaveAes = rsa.doFinal(pacote.chaveAesCifrada);
        rsa.init(Cipher.DECRYPT_MODE, parChaves.getPrivate());
        byte[] chaveHmac = rsa.doFinal(pacote.chaveHmacCifrada);

        //  Valida HMAC ANTES de decifrar Encrypt-then-MAC
        byte[] hmacCalculado = calcularHmac(chaveHmac, pacote.iv, pacote.conteudoCifrado);
        if (!MessageDigest.isEqual(hmacCalculado, pacote.hmac)) { // comparação em tempo constante
            throw new FalhaIntegridadeException("HMAC invalido: mensagem adulterada ou nao autenticada");
        }

        //  Só depois decifra o conteúdo
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chaveAes, "AES"), new IvParameterSpec(pacote.iv));
        byte[] dados = aes.doFinal(pacote.conteudoCifrado);
        return desserializar(dados);
    }

    // HMAC-SHA256 sobre (iv || conteudo). O IV entra no MAC para impedir troca sem detecção
    private static byte[] calcularHmac(byte[] chave, byte[] iv, byte[] conteudo)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(chave, "HmacSHA256"));
        mac.update(iv);
        return mac.doFinal(conteudo);
    }

    // Serializa a Mensagem em bytes para o AES cifrar
    private static byte[] serializar(Mensagem mensagem) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream saida = new ObjectOutputStream(bytes)) {
            saida.writeObject(mensagem);
        }
        return bytes.toByteArray();
    }

    // Desserializa de volta para Mensagem após decifrar
    private static Mensagem desserializar(byte[] dados) throws IOException, ClassNotFoundException {
        try (ObjectInputStream entrada = new ObjectInputStream(new ByteArrayInputStream(dados))) {
            return (Mensagem) entrada.readObject();
        }
    }

    // Exceção checked: força quem chama a tratar descarta o pacote e loga
    public static class FalhaIntegridadeException extends GeneralSecurityException {
        public FalhaIntegridadeException(String mensagem) {
            super(mensagem);
        }
    }
}