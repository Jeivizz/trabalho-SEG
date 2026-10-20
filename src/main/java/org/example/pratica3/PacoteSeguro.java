package org.example.pratica3;

import java.io.Serializable;


public class PacoteSeguro implements Serializable {
    private static final long serialVersionUID = 1L;

    public final byte[] chaveAesCifrada;
    public final byte[] chaveHmacCifrada;
    public final byte[] iv;
    public final byte[] conteudoCifrado;
    public final byte[] hmac;

    public PacoteSeguro(byte[] chaveAesCifrada, byte[] chaveHmacCifrada,
                        byte[] iv, byte[] conteudoCifrado, byte[] hmac) {
        this.chaveAesCifrada = chaveAesCifrada;
        this.chaveHmacCifrada = chaveHmacCifrada;
        this.iv = iv;
        this.conteudoCifrado = conteudoCifrado;
        this.hmac = hmac;
    }

    // Retorna uma CÓPIA com 1 bit do último byte do cifrado alterado.
    // O HMAC continua o original, então não vai bater
    public PacoteSeguro adulterar() {
        byte[] copia = conteudoCifrado.clone();
        if (copia.length > 0) {
            copia[copia.length - 1] ^= 1; // XOR de 1 bit
        }
        return new PacoteSeguro(chaveAesCifrada, chaveHmacCifrada, iv, copia, hmac);
    }
}