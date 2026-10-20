package org.example.pratica3;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.UUID;

// Serializable permite enviar o objeto inteiro via ObjectOutputStream no socket TCP.
public class Mensagem implements Serializable {
    private static final long serialVersionUID = 1L;

    // BUSCA = ida no anel; RESPOSTA = volta até a origem
    public enum Tipo { BUSCA, RESPOSTA }

    public final Tipo tipo;
    public final String id;        // UUID curto: correlaciona BUSCA com RESPOSTA
    public final int origem;       // nó que iniciou a busca
    public final String arquivo;   // nome do arquivo procurado
    public int responsavel = -1;   // quem possui o arquivo (preenchido na RESPOSTA)
    public boolean encontrado = false;
    public final ArrayList<Integer> caminho = new ArrayList<>(); // rota percorrida

    private Mensagem(Tipo tipo, String id, int origem, String arquivo) {
        this.tipo = tipo;
        this.id = id;
        this.origem = origem;
        this.arquivo = arquivo;
    }

    // Factory de BUSCA com id único 8 primeiros chars do UUID
    public static Mensagem busca(int origem, String arquivo) {
        String id = UUID.randomUUID().toString().substring(0, 8);
        return new Mensagem(Tipo.BUSCA, id, origem, arquivo);
    }

    // Converte esta BUSCA em RESPOSTA mantendo o mesmo id
    // e copiando o caminho percorrido para o log final
    public Mensagem comoResposta(int responsavel, boolean encontrado) {
        Mensagem resposta = new Mensagem(Tipo.RESPOSTA, id, origem, arquivo);
        resposta.responsavel = responsavel;
        resposta.encontrado = encontrado;
        resposta.caminho.addAll(caminho);
        return resposta;
    }

    // Formata o caminho como "P0 -> P1 -> P2 -> P3"
    public String caminhoTexto() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < caminho.size(); i++) {
            if (i > 0) sb.append(" -> ");
            sb.append("P").append(caminho.get(i));
        }
        return sb.toString();
    }
}