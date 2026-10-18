package org.example.pratica3;

import java.util.concurrent.TimeUnit;

/**
 * QUESTÃO 3 - Orquestrador dos testes.
 *
 * Sobe os 6 nós (P0..P5) em threads de uma mesma JVM, cada um com seu
 * ServerSocket TCP em localhost, e executa os casos de teste do enunciado.
 */
public class Main {

    public static void main(String[] args) throws Exception {
        NoAnel[] nos = new NoAnel[NoAnel.TOTAL_NOS];
        for (int i = 0; i < nos.length; i++) {
            nos[i] = new NoAnel(i);
            nos[i].iniciar();
        }
        Thread.sleep(300);

        titulo("CASO 1 - Busca válida: origem P0, arquivo35.ext (esperado: P0->P1->P2->P3)");
        executar(nos[0], "arquivo35.ext");

        titulo("CASO 2a - Entrada inválida: origem P1, arquivo99.ext (fora de 1-60)");
        executar(nos[1], "arquivo99.ext");

        titulo("CASO 2b - Entrada inválida: origem P4, arquivoABC.ext");
        executar(nos[4], "arquivoABC.ext");

        titulo("LOG ARMAZENADO de P3 (cada processo guarda e imprime suas mensagens)");
        nos[3].imprimirHistorico();

        for (NoAnel n : nos) {
            n.parar();
        }
    }

    private static void executar(NoAnel no, String entrada) throws InterruptedException {
        var f = no.buscar(entrada);
        if (f != null) {
            try {
                f.get(5, TimeUnit.SECONDS);
            } catch (Exception e) {
                System.out.println("Busca sem resposta: " + e.getMessage());
            }
        }
        Thread.sleep(300);
    }

    private static void titulo(String s) {
        System.out.println("\n===== " + s + " =====");
    }
}