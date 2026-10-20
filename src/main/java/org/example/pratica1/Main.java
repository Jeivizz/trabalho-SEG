package org.example.pratica1;

import java.util.Map;

// Orquestrador de demonstração: sobe o DNS em thread daemon e executa os três casos de teste 
public class Main {

    public static void main(String[] args) throws Exception {
        int porta = DnsServer.PORTA_PADRAO;

        // Sobe o DNS na mesma JVM só para a demo, em produção seria processo separado, e cada classe tem seu main() para isso
        DnsServer dns = new DnsServer(porta, DnsServer.SEGREDO_PADRAO);
        Thread t = new Thread(dns::executar, "dns");
        t.setDaemon(true);
        t.start();
        pausa(300);

        // CASO 1: Cliente 1 consulta servidor1 com handshake RSA + HMAC
        titulo("CASO 1 - Cliente 1 consulta 'servidor1' (handshake RSA + HMAC)");
        ClienteRequisitante c1 = new ClienteRequisitante("Cliente1", "localhost", porta);
        ClienteRequisitante c2 = new ClienteRequisitante("Cliente2", "localhost", porta);
        ClienteRequisitante c3 = new ClienteRequisitante("Cliente3", "localhost", porta);
        pausa(300); // espera os 3 handshakes + REGISTER

        c1.resolver("servidor1");
        pausa(600);

        // CASO 2: Registrador atualiza servidor1 -> NOTIFY cifrado para C1/C2/C3
        titulo("CASO 2 - Registrador atualiza 'servidor1' para 192.168.0.111");
        ClienteRegistrador reg = new ClienteRegistrador("localhost", porta, DnsServer.SEGREDO_PADRAO);
        Log.info("Main", "Registrador: " + reg.atualizar("servidor1", "192.168.0.111"));
        pausa(600);

        // Mostra o cache dos 3 — prova que receberam e validaram o NOTIFY
        titulo("CASO 2 - Cache dos 3 requisitantes apos NOTIFY cifrado");
        mostrar("Cliente1", c1);
        mostrar("Cliente2", c2);
        mostrar("Cliente3", c3);

        // CASO 3a: nome inexistente -> erro de entrada
        titulo("CASO 3a - Cliente 1 consulta 'servidor99' (nome inexistente)");
        c1.resolver("servidor99");
        pausa(500);

        // CASO 3b: HMAC adulterado -> DNS descarta sem processar e loga falha
        titulo("CASO 3b - Cliente 1 envia RESOLVE com HMAC adulterado");
        c1.adulterarHmac("servidor1");
        pausa(500);

        // Confirmação: nova consulta mostra que o mapa do DNS continua íntegro
        titulo("Confirmacao final - nova consulta a 'servidor1'");
        c3.resolver("servidor1");
        pausa(400);

        // Encerra tudo
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