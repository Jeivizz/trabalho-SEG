package org.example.pratica3;

import java.util.concurrent.TimeUnit;

// Orquestrador de demonstração dos três casos de teste
// Caso 1: busca válida com criptografia salto a salto (P0 -> P1 -> P2 -> P3)
// Caso 2: entradas inválidas (P1 arquivo99.ext, P4 arquivoABC.ext)
// Caso 3: pacote adulterado de P4 para P5 (falha de HMAC)

public class Main {

    public static void main(String[] args) throws Exception {
        NoAnel[] nos = new NoAnel[NoAnel.TOTAL_NOS];
        int iniciados = 0;

        try {
            // Sobe os 6 nós P0..P5
            for (int i = 0; i < nos.length; i++) {
                nos[i] = new NoAnel(i);
                nos[i].iniciar();
                iniciados++;
            }

            Thread.sleep(500);

            // CASO 1: busca válida
            titulo("CASO 1 - Busca valida: P0 procura arquivo35.ext");
            executar(nos[0], "arquivo35.ext");

            // CASO 2a: entrada inválida
            titulo("CASO 2a - Entrada invalida: P1 procura arquivo99.ext");
            executar(nos[1], "arquivo99.ext");

            // CASO 2b: entrada inválida
            titulo("CASO 2b - Entrada invalida: P4 procura arquivoABC.ext");
            executar(nos[4], "arquivoABC.ext");

            // CASO 3: pacote adulterado
            titulo("CASO 3 - Pacote adulterado: P4 envia para P5");
            nos[4].testarPacoteAdulteradoParaSucessor();
            Thread.sleep(700);

            // IMPRIME O HISTORICO DE TODOS OS NOS
            titulo("HISTORICO DE LOGS DOS NOS P0 A P5");

            for (NoAnel no : nos) {
                no.imprimirHistorico();
                System.out.println();
            }

        } finally {
            // Encerra os nós mesmo se ocorrer uma exceção
            for (int i = 0; i < iniciados; i++) {
                nos[i].parar();
            }
        }
    }

    // Executa uma busca e espera pelo resultado
    private static void executar(NoAnel no, String entrada)
            throws InterruptedException {

        var futuro = no.buscar(entrada);

        if (futuro != null) {
            try {
                futuro.get(8, TimeUnit.SECONDS);
            } catch (Exception e) {
                System.out.println(
                    "Busca sem resposta: " + e.getMessage()
                );
            }
        }

        Thread.sleep(500);
    }

    private static void titulo(String texto) {
        System.out.println("\n===== " + texto + " =====");
    }
}
