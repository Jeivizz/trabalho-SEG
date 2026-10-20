package org.example.pratica3;

import java.util.concurrent.TimeUnit;

/** Executa os cenários pedidos na questão 3 de Segurança Computacional. */
public class Main {
    public static void main(String[] args) throws Exception {
        NoAnel[] nos = new NoAnel[NoAnel.TOTAL_NOS];
        int iniciados = 0;
        try {
            for (int i = 0; i < nos.length; i++) {
                nos[i] = new NoAnel(i);
                nos[i].iniciar();
                iniciados++;
            }
            Thread.sleep(500);

            titulo("CASO 1 - Busca valida: P0 procura arquivo35.ext");
            executar(nos[0], "arquivo35.ext");

            titulo("CASO 2a - Entrada invalida: P1 procura arquivo99.ext");
            executar(nos[1], "arquivo99.ext");

            titulo("CASO 2b - Entrada invalida: P4 procura arquivoABC.ext");
            executar(nos[4], "arquivoABC.ext");

            titulo("CASO 3 - Pacote adulterado: P4 envia para P5");
            nos[4].testarPacoteAdulteradoParaSucessor();
            Thread.sleep(700);

        
        } finally {
            for (int i = 0; i < iniciados; i++) nos[i].parar();
        }
    }

    private static void executar(NoAnel no, String entrada) throws InterruptedException {
        var futuro = no.buscar(entrada);
        if (futuro != null) {
            try { futuro.get(8, TimeUnit.SECONDS); }
            catch (Exception e) { System.out.println("Busca sem resposta: " + e.getMessage()); }
        }
        Thread.sleep(500);
    }

    private static void titulo(String texto) { System.out.println("\n===== " + texto + " ====="); }
}
