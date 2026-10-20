package org.example.pratica1;

// Constantes e utilidades do protocolo de aplicação (as mesmas mensagens da
// versão sem criptografia: REGISTER, RESOLVE, UPDATE, NOTIFY...). A diferença
// é que agora elas viajam DENTRO de pacotes cifrados e autenticados.
public final class Protocolo {

    // Mensagem exigida pelo enunciado para entradas inválidas.
    public static final String MSG_ERRO_ENTRADA = "Erro na entrada de dados. Tente outra vez!";

    public static final String PAPEL_REQUISITANTE = "REQUISITANTE";
    public static final String PAPEL_REGISTRADOR = "REGISTRADOR";

    private Protocolo() {
    }

    // Recebe uma resposta "ERRO <CODIGO> ..." e diz se o erro é causado por
    // ENTRADA inválida do usuário (nome inexistente, formato ruim, IP ruim).
    // Erros como NAO_AUTORIZADO têm outro tratamento.
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
