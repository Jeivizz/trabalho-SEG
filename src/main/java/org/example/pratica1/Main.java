package org.example.pratica1;

import java.util.Map;

// QUESTÃO 1 - Orquestrador dos testes.
//
// Sobe um DnsServer em uma thread daemon e executa uma sequência de
// operações que cobre TODOS os requisitos do enunciado:
//
//   PASSO 1: três clientes requisitantes consultam nomes (inclui um
//            nome inexistente para exercitar o caminho de erro).
//   PASSO 2: um cliente registrador atualiza servidor1, servidor4 e
//            servidor9 (binding dinâmico). O servidor propaga NOTIFY.
//   PASSO 3: o registrador envia um IP inválido e um nome inexistente,
//            exercitando as validações do servidor.
//   PASSO 4: imprime o cache de cada requisitante após as notificações,
//            comprovando que o binding dinâmico chegou aos clientes.
//   PASSO 5: nova consulta confirma que o servidor persistiu a mudança.
//
// Este roteiro é a "demonstração" do trabalho no lugar de um vídeo:
// basta rodar Main e observar o console.w
public class Main {

    public static void main(String[] args) throws Exception {
        int porta = DnsServer.PORTA_PADRAO;

        // 1) servidor
        // Sobe o servidor em uma thread daemon para que possamos continuar
        // executando os clientes na thread principal.
        DnsServer dns = new DnsServer(porta);
        Thread t = new Thread(dns::executar, "dns");
        t.setDaemon(true);
        t.start();
        pausa(300);

        // tres requisitantes
        // PASSO 1 - Três clientes requisitantes fazem consultas iniciais.
        // Cada ClienteRequisitante se registra automaticamente no construtor
        // (envia REGISTER), então já estão aptos a receber NOTIFY.
        titulo("PASSO 1 - Consultas iniciais dos 3 requisitantes");
        ClienteRequisitante c1 = new ClienteRequisitante("Cliente1", "localhost", porta);
        ClienteRequisitante c2 = new ClienteRequisitante("Cliente2", "localhost", porta);
        ClienteRequisitante c3 = new ClienteRequisitante("Cliente3", "localhost", porta);
        pausa(300);

        c1.resolver("servidor1");
        c1.resolver("servidor4");
        c2.resolver("servidor9");
        c2.resolver("servidor1");
        c3.resolver("servidor4");
        c3.resolver("servidor9");
        c3.resolver("servidor10");
        c1.resolver("servidor99"); // nome inexistente deve gerar erro tratado
        pausa(600); // espera as respostas chegarem nas threads ouvintes

        // PASSO 2 - Binding dinâmico: o registrador altera três nomes.
        // O servidor responde ATUALIZADO ao registrador e propaga NOTIFY
        // a todos os clientes que enviaram REGISTER (c1, c2 e c3).
        titulo("PASSO 2 - Registrador atualiza servidor1, servidor4 e servidor9");
        ClienteRegistrador reg = new ClienteRegistrador("localhost", porta);
        System.out.println("  [Registrador] " + reg.atualizar("servidor1", "10.0.0.11"));
        System.out.println("  [Registrador] " + reg.atualizar("servidor4", "10.0.0.44"));
        System.out.println("  [Registrador] " + reg.atualizar("servidor9", "10.0.0.99"));
        pausa(600);

        // PASSO 3 - Caminhos de erro do servidor:
        //   - IP fora do formato IPv4 (999.1.1.1)      -> ERRO IP_INVALIDO
        //   - nome que não existe na tabela (servidor77) -> ERRO NAO_ENCONTRADO
        titulo("PASSO 3 - Erros tratados pelo servidor");
        System.out.println("  [Registrador] " + reg.atualizar("servidor1", "999.1.1.1"));
        System.out.println("  [Registrador] " + reg.atualizar("servidor77", "10.0.0.7"));
        pausa(400);

        // PASSO 4 - Comprovação do binding dinâmico: o cache de cada requisitante
        // deve mostrar os NOVOS valores para servidor1, servidor4 e servidor9,
        // sem que eles tenham refeito a consulta. Isso só é possível porque o
        // servidor enviou NOTIFY e a thread ouvinte de cada cliente atualizou
        // o cache local.
        titulo("PASSO 4 - Cache de cada requisitante após as notificaçoes");
        mostrar("Cliente1", c1);
        mostrar("Cliente2", c2);
        mostrar("Cliente3", c3);


        // PASSO 5 - Confirma que o servidor persistiu a mudança: uma nova
        // consulta a servidor1 deve devolver 10.0.0.11 (valor atualizado).     
        titulo("PASSO 5 - Nova consulta (confirma que o DNS guarda o valor novo)");
        c3.resolver("servidor1");
        pausa(400);


        // Encerramento limpo: fechar os clientes (envia UNREGISTER) e parar
        // o servidor (fecha o socket e interrompe o laço de recepção).
        c1.fechar();
        c2.fechar();
        c3.fechar();
        reg.fechar();
        dns.parar();
    }

    // Imprime o cache de um ClienteRequisitante em ordem alfabética
    // (copiaDoCache() devolve um TreeMap) para facilitar a leitura.
    private static void mostrar(String nome, ClienteRequisitante c) {
        System.out.print("  " + nome + ": ");
        for (Map.Entry<String, String> e : c.copiaDoCache().entrySet()) {
            System.out.print(e.getKey() + "=" + e.getValue() + "  ");
        }
        System.out.println();
    }
    // Separador visual para organizar a saída do console por passo.
    private static void titulo(String s) {
        System.out.println("\n===== " + s + " =====");
    }
    // Pequena pausa para dar tempo às threads de receberem datagramas.
    private static void pausa(long ms) throws InterruptedException {
        Thread.sleep(ms);
    }
}

