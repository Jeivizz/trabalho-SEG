package org.example.pratica1;

import java.util.Map;

// QUESTÃO 1 (Segurança) - Orquestrador dos testes.
//
// Sobe um DnsServer seguro em uma thread daemon e executa os 3 casos do
// enunciado:
//
//   CASO 1: Cliente 1 consulta "servidor1" e recebe 192.168.0.10 após
//           handshake RSA + validação de HMAC.
//   CASO 2: Registrador atualiza "servidor1" para 192.168.0.111. O DNS
//           valida o HMAC, atualiza o mapa e envia NOTIFY cifrado para
//           C1, C2 e C3. Todos validam HMAC e atualizam o cache local.
//   CASO 3: C1 envia nome inexistente (servidor99) -> DNS responde ERRO
//           e o cliente imprime "Erro na entrada de dados. Tente outra vez!".
//           C1 também envia um pacote com HMAC adulterado -> DNS descarta
//           e registra falha de integridade no log.
public class Main {

    public static void main(String[] args) throws Exception {
        int porta = DnsServer.PORTA_PADRAO;

        // 1) Sobe o servidor seguro (RSA-2048 gerado no construtor).
        DnsServer dns = new DnsServer(porta, DnsServer.SEGREDO_PADRAO);
        Thread t = new Thread(dns::executar, "dns");
        t.setDaemon(true);
        t.start();
        pausa(300);

        // ------------------------------------------------------------------
        // CASO 1 - Consulta de nome com handshake e HMAC validado
        // ------------------------------------------------------------------
        titulo("CASO 1 - Cliente 1 consulta 'servidor1' (handshake RSA + HMAC)");
        ClienteRequisitante c1 = new ClienteRequisitante("Cliente1", "localhost", porta);
        ClienteRequisitante c2 = new ClienteRequisitante("Cliente2", "localhost", porta);
        ClienteRequisitante c3 = new ClienteRequisitante("Cliente3", "localhost", porta);
        pausa(300);

        c1.resolver("servidor1");
        pausa(600);

        // ------------------------------------------------------------------
        // CASO 2 - Binding dinâmico + notificação broadcast cifrada
        // ------------------------------------------------------------------
        titulo("CASO 2 - Registrador atualiza 'servidor1' para 192.168.0.111");
        ClienteRegistrador reg = new ClienteRegistrador("localhost", porta, DnsServer.SEGREDO_PADRAO);
        Log.info("Main", "Registrador: " + reg.atualizar("servidor1", "192.168.0.111"));
        pausa(600); // espera os NOTIFY cifrados chegarem a C1, C2 e C3

        titulo("CASO 2 - Cache dos 3 requisitantes apos NOTIFY cifrado");
        mostrar("Cliente1", c1);
        mostrar("Cliente2", c2);
        mostrar("Cliente3", c3);

        // ------------------------------------------------------------------
        // CASO 3a - Entrada inválida (nome inexistente)
        // ------------------------------------------------------------------
        titulo("CASO 3a - Cliente 1 consulta 'servidor99' (nome inexistente)");
        c1.resolver("servidor99");
        pausa(500);

        // ------------------------------------------------------------------
        // CASO 3b - HMAC adulterado (deve ser descartado sem processar)
        // ------------------------------------------------------------------
        titulo("CASO 3b - Cliente 1 envia RESOLVE com HMAC adulterado");
        c1.adulterarHmac("servidor1"); // método público do ClienteRequisitante
        pausa(500);

        // ------------------------------------------------------------------
        // Confirmação final: o DNS guardou o valor novo?
        // ------------------------------------------------------------------
        titulo("Confirmacao final - nova consulta a 'servidor1'");
        c3.resolver("servidor1");
        pausa(400);

        // Encerramento: fecha os sockets dos clientes e para o servidor.
        c1.fechar();
        c2.fechar();
        c3.fechar();
        reg.fechar();
        dns.parar();
    }

    private static void mostrar(String nome, ClienteRequisitante c) {
        System.out.print("  " + nome + ": ");
        for (Map.Entry<String, String> e : c.copiaDoCache().entrySet()) {
            System.out.print(e.getKey() + "=" + e.getValue() + "  ");
        }
        System.out.println();
    }

    private static void titulo(String s) {
        System.out.println("\n===== " + s + " =====");
    }

    private static void pausa(long ms) throws InterruptedException {
        Thread.sleep(ms);
    }
}