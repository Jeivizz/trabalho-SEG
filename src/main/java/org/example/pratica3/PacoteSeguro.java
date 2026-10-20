package org.example.pratica3;

import java.io.Serializable;

/** Envelope transmitido pela rede. O conteúdo e as chaves simétricas ficam protegidos. */
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

    /** Retorna uma cópia adulterada para o teste de falha de integridade. */
    public PacoteSeguro adulterar() {
        byte[] copia = conteudoCifrado.clone();
        if (copia.length > 0) {
            copia[copia.length - 1] ^= 1;
        }
        return new PacoteSeguro(chaveAesCifrada, chaveHmacCifrada, iv, copia, hmac);
    }
}
