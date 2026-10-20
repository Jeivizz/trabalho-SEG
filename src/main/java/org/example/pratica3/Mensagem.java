package org.example.pratica3;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.UUID;

/** Mensagem lógica da busca P2P. Ela é serializada e criptografada antes de ir à rede. */
public class Mensagem implements Serializable {
    private static final long serialVersionUID = 1L;

    public enum Tipo { BUSCA, RESPOSTA }

    public final Tipo tipo;
    public final String id;
    public final int origem;
    public final String arquivo;
    public int responsavel = -1;
    public boolean encontrado = false;
    public final ArrayList<Integer> caminho = new ArrayList<>();

    private Mensagem(Tipo tipo, String id, int origem, String arquivo) {
        this.tipo = tipo;
        this.id = id;
        this.origem = origem;
        this.arquivo = arquivo;
    }

    public static Mensagem busca(int origem, String arquivo) {
        String id = UUID.randomUUID().toString().substring(0, 8);
        return new Mensagem(Tipo.BUSCA, id, origem, arquivo);
    }

    public Mensagem comoResposta(int responsavel, boolean encontrado) {
        Mensagem resposta = new Mensagem(Tipo.RESPOSTA, id, origem, arquivo);
        resposta.responsavel = responsavel;
        resposta.encontrado = encontrado;
        resposta.caminho.addAll(caminho);
        return resposta;
    }

    public String caminhoTexto() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < caminho.size(); i++) {
            if (i > 0) sb.append(" -> ");
            sb.append("P").append(caminho.get(i));
        }
        return sb.toString();
    }
}
