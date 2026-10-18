package org.example.pratica1;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

//QUESTÃO 1 - Cliente requisitante.

// Usa um único DatagramSocket. Uma thread "ouvinte" fica sempre recebendo
// datagramas, porque o servidor pode enviar a qualquer momento:
//   - RESOLVIDO ...  (resposta a uma consulta)
//   - NOTIFY ...     (atualização iniciada pelo servidor - binding dinâmico)
// Assim a thread principal pode continuar enviando consultas sem bloquear.
//
// O cliente mantém um cache local (nome -> ip) atualizado tanto pelas
// respostas (RESOLVIDO) quanto pelas notificações (NOTIFY). Esse cache
// é o que materializa o "binding dinâmico" do ponto de vista do cliente:
// ele vê o valor mudar sem precisar perguntar de novo.
//
// Decisão importante: NÃO usamos setSoTimeout no socket deste cliente.
// A thread ouvinte precisa bloquear indefinidamente em receive() para
// capturar NOTIFY a qualquer momento. Um timeout aqui causaria perda
// de notificações. (O ClienteRegistrador, por outro lado, usa timeout
// porque ele apenas envia e espera uma confirmação pontual.)


 
public class ClienteRequisitante {

    private final String nome;
    private final DatagramSocket socket;
    private final InetSocketAddress servidor;
    //Cache local de resoluções. ConcurrentHashMap porque a thread ouvinte
    //escreve (RESOLVIDO / NOTIFY) enquanto a thread principal lê (cache).
    private final Map<String, String> cache = new ConcurrentHashMap<>();
    //lag volátil para encerrar a thread ouvinte de forma limpa quando
    //fechar() for chamado. volatile garante visibilidade entre threads.
    private volatile boolean ativo = true;

    public ClienteRequisitante(String nome, String host, int portaServidor) throws IOException {
        this.nome = nome;
    // Porta efêmera escolhida pelo SO. O servidor responderá para este
    // mesmo endereço (IP + porta), então precisamos manter o socket aberto.
    this.socket = new DatagramSocket();
    this.servidor = new InetSocketAddress(InetAddress.getByName(host), portaServidor);

    // Thread ouvinte em modo daemon: se o usuário encerrar o programa
    // sem chamar fechar(), ela não impede a JVM de terminar.
    Thread ouvinte = new Thread(this::escutar, nome + "-ouvinte");
    ouvinte.setDaemon(true);
    ouvinte.start();

    // REGISTER explícito: é isso que nos coloca na lista de clientes que
    // recebem NOTIFY. O enunciado exige que atualizações cheguem aos
    // requisitantes — sem este passo, o servidor não saberia para onde
    // enviar as notificações.
    enviar("REGISTER");
    }

    // Envia uma consulta ao servidor. A resposta NÃO é lida aqui: ela chega
    // na thread ouvinte e é interpretada em interpretar(). Isso evita que
    // a thread principal fique bloqueada esperando uma resposta específica
    // enquanto outras mensagens (ex.: NOTIFY) podem chegar.
    public void resolver(String nomeServidor) {
        enviar("RESOLVE " + nomeServidor);
    }

    public String consultarCache(String nomeServidor) {
        return cache.get(nomeServidor);
    }

    public Map<String, String> copiaDoCache() {
        return new TreeMap<>(cache);
    }

    public void fechar() {
        enviar("UNREGISTER");
        ativo = false;
        socket.close();
    }

    private void enviar(String texto) {
        byte[] dados = texto.getBytes(StandardCharsets.UTF_8);
        try {
            socket.send(new DatagramPacket(dados, dados.length, servidor));
        } catch (IOException e) {
            imprimir("Falha ao enviar \"" + texto + "\": " + e.getMessage());
        }
    }
    //  Laço da thread ouvinte. Bloqueia em receive() até chegar um datagrama
    //  e o interpreta. Sai do laço quando o socket é fechado (fechar()).
    private void escutar() {
        while (ativo) {
            DatagramPacket pacote = new DatagramPacket(new byte[1024], 1024);
            try {
                socket.receive(pacote);
            } catch (IOException e) {
                break; // socket fechado
            }
            String texto = new String(pacote.getData(), 0, pacote.getLength(), StandardCharsets.UTF_8).trim();
            interpretar(texto);
        }
    }

        // Interpreta mensagens vindas do servidor. O protocolo está documentado
        // em DnsServer. Mensagens desconhecidas são registradas no console para
        // facilitar o diagnóstico, mas não derrubam o cliente.
    private void interpretar(String texto) {
        String[] t = texto.split("\\s+");
        if (t[0].equals("RESOLVIDO") && t.length == 3) {
            cache.put(t[1], t[2]);
            imprimir("Resposta do DNS: " + t[1] + " -> " + t[2]);
        } else if (t[0].equals("NOTIFY") && t.length == 3) {
              // Binding dinâmico: o servidor avisa que o IP mudou. Atualizamos o
              // cache local. A partir daqui, consultarCache() já devolve o novo IP.
            String antigo = cache.put(t[1], t[2]);
           imprimir("*** NOTIFICAÇÃO: " + t[1] + " mudou"
        + (antigo != null ? " de " + antigo : " (não estava no cache)")
        + " para " + t[2]);
        } else if (t[0].equals("REGISTRADO")) {
            imprimir("Registrado no servidor para receber atualizações");
        } else if (t[0].equals("DESREGISTRADO")) {
            imprimir("Desregistrado; não receberá mais atualizações");
        } else if (t[0].equals("ERRO")) {
            imprimir("Erro do servidor: " + texto.substring(4).trim());
        } else {
            imprimir("Mensagem desconhecida: \"" + texto + "\"");
        }
    }

    private void imprimir(String texto) {
        System.out.println("  [" + nome + "] " + texto);
    }

    // Modo interativo: java ClienteRequisitante Cliente1 [host] [porta] 
    public static void main(String[] args) throws Exception {
        String nome = args.length > 0 ? args[0] : "Cliente1";
        String host = args.length > 1 ? args[1] : "localhost";
        int porta = args.length > 2 ? Integer.parseInt(args[2]) : DnsServer.PORTA_PADRAO;

        ClienteRequisitante c = new ClienteRequisitante(nome, host, porta);
        System.out.println("Comandos: resolver <nome> | cache | sair");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String linha;
        while ((linha = in.readLine()) != null) {
            linha = linha.trim();
            if (linha.equals("sair")) {
                break;
            } else if (linha.equals("cache")) {
                System.out.println(c.copiaDoCache());
            } else if (linha.startsWith("resolver ") && linha.length() > 9) {
                c.resolver(linha.substring(9).trim());
            } else if (!linha.isEmpty()) {
                System.out.println("Comando inválido. Use: resolver <nome> | cache | sair");
            }
        }
        c.fechar();
    }



}
