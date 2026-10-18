package org.example.pratica3;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.UUID;

/**
 * QUESTÃO 3 - Mensagem composta trocada entre os nós do anel.
 *
 * É um objeto Serializable enviado com ObjectOutputStream sobre TCP
 * (mensagem "composta": mistura String, int, boolean, enum e List).
 *
 * Dois tipos:
 *   BUSCA    - viaja no sentido horário: P(i) -> P(i+1), até achar o responsável.
 *   RESPOSTA - volta pelo caminho inverso (via antecessor) até a origem.
 *
 * O campo "caminho" registra por quais nós a busca passou (P0, P1, P2...).
 */
public class Mensagem implements Serializable {

    private static final long serialVersionUID = 1L;

    public enum Tipo { BUSCA, RESPOSTA }

    public final Tipo tipo;
    public final String id;        // identifica a busca (liga BUSCA e RESPOSTA)
    public final int origem;       // nó que iniciou a busca
    public final String arquivo;   // arquivo procurado
    public int responsavel = -1;   // nó que possui o arquivo (preenchido na RESPOSTA)
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

    // Cria a RESPOSTA correspondente a esta BUSCA, copiando o caminho percorrido. 
    public Mensagem comoResposta(int responsavel, boolean encontrado) {
        Mensagem r = new Mensagem(Tipo.RESPOSTA, id, origem, arquivo);
        r.responsavel = responsavel;
        r.encontrado = encontrado;
        r.caminho.addAll(caminho);
        return r;
    }

    public String caminhoTexto() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < caminho.size(); i++) {
            if (i > 0) {
                sb.append(" -> ");
            }
            sb.append("P").append(caminho.get(i));
        }
        return sb.toString();
    }
}

