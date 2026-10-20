package org.example.pratica1;

import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;


public class Sessao {

    public final String id;
    public final String papel;     // REQUISITANTE ou REGISTRADOR
    public final String nome;      // nome só para logs (C1, C2, Registrador...)
    private final byte[] chaveAes;
    private final byte[] chaveMac;

    // Usados apenas no servidor: para onde enviar NOTIFY e se o cliente pediu REGISTER.
    public volatile SocketAddress endereco;
    public volatile boolean notificar;

    public Sessao(String id, byte[] chaveAes, byte[] chaveMac, String papel, String nome, SocketAddress endereco) {
        this.id = id;
        this.chaveAes = chaveAes;
        this.chaveMac = chaveMac;
        this.papel = papel;
        this.nome = nome;
        this.endereco = endereco;
    }

    public String rotulo() {
        return "sessao " + id.substring(0, 6) + " " + nome;
    }

    // ------------------------------------------------------------------
    // Enviar: cifra + HMAC
    // ------------------------------------------------------------------
    public String empacotar(String claro) {
        try {
            byte[] iv = CriptoUtil.aleatorios(CriptoUtil.TAM_IV);
            byte[] cifrado = CriptoUtil.aesCifrar(chaveAes, iv, claro.getBytes(StandardCharsets.UTF_8));
            String corpo = id + "|" + CriptoUtil.b64(iv) + "|" + CriptoUtil.b64(cifrado);
            byte[] tag = CriptoUtil.hmac(chaveMac, corpo.getBytes(StandardCharsets.UTF_8));
            return "DATA|" + corpo + "|" + CriptoUtil.b64(tag);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("erro criptografico ao empacotar", e);
        }
    }

    // ------------------------------------------------------------------
    // Receber: valida HMAC -> decifra. A ORDEM importa: nada é decifrado
    // nem interpretado antes de o HMAC ser aprovado.
    // ------------------------------------------------------------------
    public String abrir(String pacote) throws FalhaIntegridadeException {
        String[] p = pacote.split("\\|", -1);
        if (p.length != 5 || !p[0].equals("DATA")) {
            throw new FalhaIntegridadeException("formato de pacote invalido");
        }
        if (!p[1].equals(id)) {
            throw new FalhaIntegridadeException("pacote de outra sessao");
        }

        try {
            // 1) HMAC
            byte[] recebido = CriptoUtil.deb64(p[4]);
            byte[] esperado = CriptoUtil.hmac(chaveMac,
                    (p[1] + "|" + p[2] + "|" + p[3]).getBytes(StandardCharsets.UTF_8));
            if (!CriptoUtil.iguais(recebido, esperado)) {
                throw new FalhaIntegridadeException("HMAC invalido (pacote adulterado ou chave incorreta)");
            }

            // 2) Decifrar
            byte[] iv = CriptoUtil.deb64(p[2]);
            if (iv.length != CriptoUtil.TAM_IV) {
                throw new FalhaIntegridadeException("IV com tamanho invalido");
            }
            byte[] claro = CriptoUtil.aesDecifrar(chaveAes, iv, CriptoUtil.deb64(p[3]));
            return new String(claro, StandardCharsets.UTF_8);

        } catch (IllegalArgumentException e) { // Base64 ruim
            throw new FalhaIntegridadeException("campos malformados no pacote");
        } catch (GeneralSecurityException e) {
            throw new FalhaIntegridadeException("falha ao decifrar");
        }
    }

    // ------------------------------------------------------------------
    // Utilidades estáticas (usadas antes de existir um objeto Sessao)
    // ------------------------------------------------------------------

    // Extrai o idSessao do cabeçalho em claro, só para o servidor escolher
    // qual chave usar. Não é confiável até o HMAC ser validado.
    public static String extrairId(String pacote) {
        String[] p = pacote.split("\\|", -1);
        return p.length == 5 ? p[1] : null;
    }

    // Resumo para os logs: mostra que o tráfego está mesmo cifrado.
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