package org.example.pratica1;

public final class Protocolo {

    // Texto para entradas inválidas
    public static final String MSG_ERRO_ENTRADA = "Erro na entrada de dados. Tente outra vez!";

    // Papéis definidos no handshake. O papel REGISTRADOR tem permissão de UPDATE;
    // o REQUISITANTE só pode RESOLVE/REGISTER.
    public static final String PAPEL_REQUISITANTE = "REQUISITANTE";
    public static final String PAPEL_REGISTRADOR = "REGISTRADOR";

    private Protocolo() {
    }

    // Diz se uma resposta "ERRO <motivo>" corresponde a erro de ENTRADA
    // (nome inexistente, formato inválido, requisição inválida, IP inválido).
    // Usado para imprimir a mensagem padronizada do PDF no cliente.
    public static boolean ehErroDeEntrada(String resposta) {
        String[] t = resposta.trim().split("\\s+");
        if (t.length < 2 || !t[0].equals("ERRO")) {
            return false;
        }
        switch (t[1]) {
            case "NAO_ENCONTRADO":
            case "FORMATO_INVALIDO":
            case "REQUISICAO_INVALIDA":
            case "IP_INVALIDO":
                return true;
            default:
                return false;
        }
    }
}

//>.<