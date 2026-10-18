package org.example.pratica3;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * QUESTÃO 3 - Um nó (processo Pi) do anel P2P.
 *
 * Cada nó:
 *  - tem um identificador numérico (0..5) e escuta em TCP na porta PORTA_BASE + id;
 *  - conhece o sucessor (id+1) e o antecessor (id-1), com aritmética módulo 6;
 *  - guarda 10 arquivos (simulados por Strings): Pi tem arquivos 10*i+1 .. 10*i+10;
 *  - NÃO existe servidor central: a busca é repassada de nó em nó (sentido horário).
 *
 * Multithread: uma thread aceita conexões; cada conexão recebida é tratada por
 * outra thread do pool. A thread principal (console) pode iniciar buscas ao mesmo
 * tempo em que o nó atende mensagens de outros.
 *
 * Fluxo de uma busca (ex.: P0 procura arquivo35.ext):
 *   P0 -BUSCA-> P1 -BUSCA-> P2 -BUSCA-> P3 (tem!)
 *   P0 <-RESPOSTA- P1 <-RESPOSTA- P2 <-RESPOSTA- P3   (volta pelos antecessores)
 */
public class NoAnel {

    public static final int TOTAL_NOS = 6;
    public static final int ARQUIVOS_POR_NO = 10;
    public static final int TOTAL_ARQUIVOS = TOTAL_NOS * ARQUIVOS_POR_NO;
    public static final int PORTA_BASE = 7000;
    public static final String MSG_ERRO_ENTRADA = "Erro na entrada de dados. Tente outra vez!";

    // Formato aceito: arquivo<N>.ext, N inteiro positivo sem zeros à esquerda. 
    private static final Pattern FORMATO = Pattern.compile("^arquivo([1-9][0-9]{0,8})\\.ext$");
    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private final int id;
    private final int sucessor;
    private final int antecessor;
    private final Set<String> arquivos = new HashSet<>(); // somente leitura após o construtor
    // Buscas iniciadas por este nó que ainda aguardam RESPOSTA (idBusca -> futuro). 
    private final Map<String, CompletableFuture<Mensagem>> pendentes = new ConcurrentHashMap<>();
    private final List<String> historico = Collections.synchronizedList(new ArrayList<>());
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    });
    private ServerSocket servidor;

    public NoAnel(int id) {
        this.id = id;
        this.sucessor = (id + 1) % TOTAL_NOS;
        this.antecessor = (id + TOTAL_NOS - 1) % TOTAL_NOS;
        for (int k = id * ARQUIVOS_POR_NO + 1; k <= (id + 1) * ARQUIVOS_POR_NO; k++) {
            arquivos.add("arquivo" + k + ".ext");
        }
    }

    public int getId() {
        return id;
    }

    // ------------------------------------------------------------------
    // Ciclo de vida
    // ------------------------------------------------------------------

    public void iniciar() throws IOException {
        servidor = new ServerSocket(PORTA_BASE + id, 50, InetAddress.getLoopbackAddress());
        Thread aceitador = new Thread(this::aceitarConexoes, "P" + id + "-aceitador");
        aceitador.setDaemon(true);
        aceitador.start();
        log("No iniciado na porta " + (PORTA_BASE + id) + " | sucessor=P" + sucessor
                + " antecessor=P" + antecessor
                + " | arquivos " + (id * ARQUIVOS_POR_NO + 1) + " a " + ((id + 1) * ARQUIVOS_POR_NO));
    }

    public void parar() {
        try {
            if (servidor != null) {
                servidor.close();
            }
        } catch (IOException ignorado) {
            // encerrando de qualquer forma
        }
    }

    private void aceitarConexoes() {
        while (!servidor.isClosed()) {
            try {
                Socket s = servidor.accept();
                pool.execute(() -> tratarConexao(s));
            } catch (IOException e) {
                if (!servidor.isClosed()) {
                    log("Erro ao aceitar conexao: " + e.getMessage());
                }
            }
        }
    }

    private void tratarConexao(Socket s) {
        try (Socket socket = s; ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            Mensagem m = (Mensagem) in.readObject();
            if (m.tipo == Mensagem.Tipo.BUSCA) {
                processarBusca(m);
            } else {
                processarResposta(m);
            }
        } catch (Exception e) {
            log("Mensagem invlida/erro de leitura descartado: " + e);
        }
    }

    // ------------------------------------------------------------------
    // Iniciar uma busca (chamado pelo console deste nó)
    // ------------------------------------------------------------------

    /**
     * Valida a entrada e, se válida, inicia a busca no anel.
     *
     * @return futuro que completa quando a RESPOSTA chega; ou null se a entrada
     *         for inválida (nesse caso NADA é enviado ao anel).
     */
    public CompletableFuture<Mensagem> buscar(String entrada) {
        String arq = entrada == null ? "" : entrada.trim();
        Matcher m = FORMATO.matcher(arq);
        if (!m.matches() || Integer.parseInt(m.group(1)) > TOTAL_ARQUIVOS) {
            System.out.println(MSG_ERRO_ENTRADA);
            historico.add(hora() + " [P" + id + "] Entrada rejeitada: \"" + arq + "\"");
            return null;
        }

        log("Usurio pediu busca de '" + arq + "'");
        CompletableFuture<Mensagem> futuro = new CompletableFuture<>();

        if (arquivos.contains(arq)) { // já é meu: não precisa usar a rede
            Mensagem local = Mensagem.busca(id, arq);
            local.caminho.add(id);
            log("RESULTADO: '" + arq + "' e local (P" + id + "), nenhuma mensagem enviada");
            futuro.complete(local.comoResposta(id, true));
            return futuro;
        }

        Mensagem busca = Mensagem.busca(id, arq);
        busca.caminho.add(id);
        pendentes.put(busca.id, futuro);
        if (!enviar(busca, sucessor)) {
            pendentes.remove(busca.id);
            futuro.completeExceptionally(new IOException("sucessor P" + sucessor + " inacessivel"));
        }
        return futuro;
    }

    // ------------------------------------------------------------------
    // Tratamento das mensagens recebidas
    // ------------------------------------------------------------------

    private void processarBusca(Mensagem m) {
        int remetente = m.caminho.get(m.caminho.size() - 1);
        log("RECEBEU  BUSCA[" + m.id + "] '" + m.arquivo + "' de P" + remetente + " (origem P" + m.origem + ")");

        if (m.origem == id) { // a busca deu a volta completa sem achar ninguém
            log("A busca deu a volta no anel: arquivo inexistente");
            concluir(m.comoResposta(-1, false));
            return;
        }

        m.caminho.add(id);
        if (arquivos.contains(m.arquivo)) {
            log("Possuo '" + m.arquivo + "'. Respondendo pelo antecessor P" + antecessor);
            enviar(m.comoResposta(id, true), antecessor);
        } else {
            log("Nao possuo '" + m.arquivo + "'. Repassando ao sucessor P" + sucessor);
            enviar(m, sucessor);
        }
    }

    private void processarResposta(Mensagem m) {
        log("RECEBEU  RESPOSTA[" + m.id + "] '" + m.arquivo + "' de P" + sucessor);
        if (m.origem == id) {
            concluir(m);
        } else {
            log("Nao sou a origem. Repassando resposta ao antecessor P" + antecessor);
            enviar(m, antecessor);
        }
    }

    private void concluir(Mensagem m) {
        if (m.encontrado) {
            log("RESULTADO: '" + m.arquivo + "' encontrado em P" + m.responsavel
                    + " | caminho da busca: " + m.caminhoTexto());
        } else {
            log("RESULTADO: '" + m.arquivo + "' NAO encontrado no anel");
        }
        CompletableFuture<Mensagem> f = pendentes.remove(m.id);
        if (f != null) {
            f.complete(m);
        }
    }

    // ------------------------------------------------------------------
    // Envio (um socket TCP novo por mensagem)
    // ------------------------------------------------------------------

    private boolean enviar(Mensagem m, int destino) {
        // o log vem ANTES do envio para a ordem dos logs refletir a causalidade
        log("ENVIOU   " + m.tipo + "[" + m.id + "] '" + m.arquivo + "' para P" + destino);
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), PORTA_BASE + destino);
             ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream())) {
            out.writeObject(m);
            out.flush();
            return true;
        } catch (IOException e) {
            log("FALHA ao enviar para P" + destino + ": " + e.getMessage());
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Log
    // ------------------------------------------------------------------

    private static String hora() {
        return "[" + LocalTime.now().format(HORA) + "]";
    }

    private void log(String texto) {
        String linha = hora() + " [P" + id + "] " + texto;
        historico.add(linha);
        System.out.println(linha);
    }

    public void imprimirHistorico() {
        System.out.println("---- Log de P" + id + " (" + historico.size() + " entradas) ----");
        synchronized (historico) {
            for (String linha : historico) {
                System.out.println(linha);
            }
        }
    }

    // ------------------------------------------------------------------
    // Modo "um processo por terminal": java NoAnel <id 0..5>
    // ------------------------------------------------------------------

    
}

