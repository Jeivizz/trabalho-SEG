package org.example.pratica1;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;


public class DnsServer {

    public static final int PORTA_PADRAO = 5300; // 5353 é usada pelo mDNS em muitos SOs e causariria conflito de port

    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private final DatagramSocket socket;

    // nome -> endereço. ConcurrentHashMap porque várias threads leem(RESOLVE)/escrevem(UPDATE) 
    // simultaneamente, um HashMap comum poderia corrompera estrutura interna 
private final Map<String, String> tabela = new ConcurrentHashMap<>();

    // Endereços (ip:porta UDP) dos clientes requisitantes que devem receber NOTIFY. 
    private final Set<SocketAddress> requisitantes = ConcurrentHashMap.newKeySet();

    // Pool de threads para tratar datagramas recebidos. Usamos newCachedThreadPool
    // porque cada requisição é curta (parse + resposta) e o número de clientes
    // simultâneos é pequeno. As threads são daemon para não impedir o
    // encerramento da JVM quando o servidor for parado.  
    private final ExecutorService pool;
    private volatile boolean ativo = true;

    public DnsServer(int porta) throws SocketException {
        this.socket = new DatagramSocket(porta);
        //   Carga inicial exigida pela questão
        //  "servidor1" → "192.168.0.10"
        //  "servidor2" → "192.168.0.20"
        //  "servidor3" → "192.168.0.30"
        //  "servidor4" → "192.168.0.40"
        //  "servidor5" → "192.168.0.50"
        //  "servidor6" → "192.168.0.60"
        //  "servidor7" → "192.168.0.70"
        //  "servidor8" → "192.168.0.80"
        //  "servidor9" → "192.168.0.90"
        //  "servidor10" → "192.168.0.100"
        for (int i = 1; i <= 10; i++) {
            tabela.put("servidor" + i, "192.168.0." + (i * 10));
        }
        this.pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
    }

    // Laço principal: recebe datagramas e delega o tratamento ao pool. 
    public void executar() {
        log("Mini-DNS escutando em UDP/" + socket.getLocalPort() + " com " + tabela.size() + " registros");
        while (ativo) {
            DatagramPacket pacote = new DatagramPacket(new byte[1024], 1024);
            try {
                socket.receive(pacote);
            } catch (IOException e) {
                if (ativo) {
                    log("Erro de E/S ao receber: " + e.getMessage());
                }
                break;
            }
            pool.execute(() -> tratar(pacote));
        }
    }

    public void parar() {
        ativo = false;
        socket.close();
    }

    // Processa uma mensagem recebida. O protocolo é textual e cada mensagem
    // começa por um verbo (REGISTER, UNREGISTER, RESOLVE, UPDATE). Verbos
    // desconhecidos ou malformados resultam em ERRO REQUISICAO_INVALIDA,
    // para que o cliente saiba que a mensagem não foi entendida. 
    private void tratar(DatagramPacket pacote) {
        String msg = new String(pacote.getData(), pacote.getOffset(), pacote.getLength(),
                StandardCharsets.UTF_8).trim();
        SocketAddress remetente = pacote.getSocketAddress();
        log("RECEBIDO de " + remetente + ": \"" + msg + "\"");

        String[] t = msg.split("\\s+");
        switch (t[0].toUpperCase()) {
            case "REGISTER":
                requisitantes.add(remetente);
                enviar("REGISTRADO", remetente);
                break;

            case "UNREGISTER":
                requisitantes.remove(remetente);
                enviar("DESREGISTRADO", remetente);
                break;

            case "RESOLVE":
                if (t.length != 2) {
                    enviar("ERRO REQUISICAO_INVALIDA", remetente);
                    break;
                }
                
                String nome = t[1].toLowerCase();
                String ip = tabela.get(nome);
                enviar(ip != null ? "RESOLVIDO " + nome + " " + ip : "ERRO NAO_ENCONTRADO " + nome, remetente);
                break;

            case "UPDATE":
                atualizar(t, remetente);
                break;

            default:
                enviar("ERRO REQUISICAO_INVALIDA", remetente);
        }
    }

    // Binding dinâmico
    // Passos:
    //   1. Valida o formato da mensagem (UPDATE <nome> <ip>).
    //   2. Verifica se o nome existe na tabela (não criamos entradas novas).
    //   3. Valida o IPv4 com regex (evita propagar lixo para os clientes).
    //   4. Atualiza a tabela e responde ATUALIZADO ao registrador.
    //   5. Propaga NOTIFY a todos os clientes previamente registrados.
    //
    // A propagação é feita de forma "melhor esforço" (UDP não garante entrega).
    // O cliente que não receber um NOTIFY ainda pode consultar via RESOLVE,
    // então o sistema continua correto, apenas menos eficiente.
    private void atualizar(String[] t, SocketAddress registrador) {
        if (t.length != 3) {
            enviar("ERRO REQUISICAO_INVALIDA", registrador);
            return;
        }
        String nome = t[1].toLowerCase();
        String novoIp = t[2];
        if (!tabela.containsKey(nome)) {
            enviar("ERRO NAO_ENCONTRADO " + nome, registrador);
            return;
        }
        if (!IPV4.matcher(novoIp).matches()) {
            enviar("ERRO IP_INVALIDO " + novoIp, registrador);
            return;
        }
        String antigo = tabela.put(nome, novoIp);
        log("ATUALIZADO " + nome + ": " + antigo + " -> " + novoIp);
        enviar("ATUALIZADO " + nome + " " + novoIp, registrador);

        log("Propagando NOTIFY para " + requisitantes.size() + " requisitante(s)");
        for (SocketAddress cliente : requisitantes) {
            enviar("NOTIFY " + nome + " " + novoIp, cliente);
        }
    }
    // Envia uma resposta textual via UDP. Como UDP não garante entrega,
    // capturamos IOException para que uma falha em um destinatário não
    // derrube o servidor nem impeça os demais de receberem a mensagem.
    private void enviar(String texto, SocketAddress destino) {
        byte[] dados = texto.getBytes(StandardCharsets.UTF_8);
        try {
            socket.send(new DatagramPacket(dados, dados.length, destino));
            log("ENVIADO para " + destino + ": \"" + texto + "\"");
        } catch (IOException e) {
            log("Falha ao enviar para " + destino + ": " + e.getMessage());
        }
    }

    private static void log(String texto) {
        System.out.println("[" + LocalTime.now().format(HORA) + "] [DNS] " + texto);
    }

    public static void main(String[] args) throws Exception {
        int porta = args.length > 0 ? Integer.parseInt(args[0]) : PORTA_PADRAO;
        new DnsServer(porta).executar();
    }
}
