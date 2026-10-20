package org.example.pratica1;

import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;


public class Sessao {

    public final String id;        // 8 bytes em hex, identifica a sessão
    public final String papel;     // REQUISITANTE ou REGISTRADOR
    public final String nome;      // nome do cliente
    private final byte[] chaveAes; // AES-256
    private final byte[] chaveMac; // HMAC-SHA256

    public volatile SocketAddress endereco; // atualizado a cada pacote recebido
    public volatile boolean notificar;      // true se fez REGISTER (recebe NOTIFY)

    public Sessao(String id, byte[] chaveAes, byte[] chaveMac, String papel, String nome, SocketAddress endereco) {
        this.id = id;
        this.chaveAes = chaveAes;
        this.chaveMac = chaveMac;
        this.papel = papel;
        this.nome = nome;
        this.endereco = endereco;
    }

    // Rótulo curto para os logs: "sessao abc123 Cliente1"
    public String rotulo() {
        return "sessao " + id.substring(0, 6) + " " + nome;
    }

    // Empacota: Encrypt-then-MAC (AES-CBC + HMAC-SHA256 sobre id|iv|cifrado).
    // O id entra no HMAC para impedir que pacote de outra sessão seja aceito.
    public String empacotar(String claro) {
        try {
            byte[] iv = CriptoUtil.aleatorios(CriptoUtil.TAM_IV); // IV novo a cada pacote
            byte[] cifrado = CriptoUtil.aesCifrar(chaveAes, iv, claro.getBytes(StandardCharsets.UTF_8));
            String corpo = id + "|" + CriptoUtil.b64(iv) + "|" + CriptoUtil.b64(cifrado);
            byte[] tag = CriptoUtil.hmac(chaveMac, corpo.getBytes(StandardCharsets.UTF_8));
            return "DATA|" + corpo + "|" + CriptoUtil.b64(tag);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("erro criptografico ao empacotar", e);
        }
    }

    // Desempacota: valida formato, id da sessão, HMAC tempo constante e só então decifra.
    // Qualquer falha vira FalhaIntegridadeException -> pacote descartado pelo chamador.
    public String abrir(String pacote) throws FalhaIntegridadeException {
        String[] p = pacote.split("\\|", -1);
        if (p.length != 5 || !p[0].equals("DATA")) {
            throw new FalhaIntegridadeException("formato de pacote invalido");
        }
        if (!p[1].equals(id)) {
            throw new FalhaIntegridadeException("pacote de outra sessao");
        }

        try {
            // Valida HMAC ANTES de decifrar (Encrypt-then-MAC)
            byte[] recebido = CriptoUtil.deb64(p[4]);
            byte[] esperado = CriptoUtil.hmac(chaveMac,
                    (p[1] + "|" + p[2] + "|" + p[3]).getBytes(StandardCharsets.UTF_8));
            if (!CriptoUtil.iguais(recebido, esperado)) {
                throw new FalhaIntegridadeException("HMAC invalido (pacote adulterado ou chave incorreta)");
            }

            // Só depois decifra
            byte[] iv = CriptoUtil.deb64(p[2]);
            if (iv.length != CriptoUtil.TAM_IV) {
                throw new FalhaIntegridadeException("IV com tamanho invalido");
            }
            byte[] claro = CriptoUtil.aesDecifrar(chaveAes, iv, CriptoUtil.deb64(p[3]));
            return new String(claro, StandardCharsets.UTF_8);

        } catch (IllegalArgumentException e) { // Base64 inválido
            throw new FalhaIntegridadeException("campos malformados no pacote");
        } catch (GeneralSecurityException e) { // falha no AES
            throw new FalhaIntegridadeException("falha ao decifrar");
        }
    }

    // Extrai o id da sessão do pacote, usado pelo servidor para achar a sessão
    public static String extrairId(String pacote) {
        String[] p = pacote.split("\\|", -1);
        return p.length == 5 ? p[1] : null;
    }

    // Resumo para log: mostra que o pacote é cifrado (tamanho + prefixo), sem expor claro
    public static String resumo(String pacote) {
        String[] p = pacote.split("\\|", -1);
        if (p.length != 5) {
            return "(pacote malformado)";
        }
        try {
            return "cifrado[" + CriptoUtil.deb64(p[3]).length + " bytes]="
                    + CriptoUtil.abreviar(p[3], 16) + " hmac=" + CriptoUtil.abreviar(p[4], 12);
        } catch (IllegalArgumentException e) {
            return "(pacote malformado)";
        }
    }
}