package org.example.pratica3;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
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

// Nó do anel P2P. Cada conexão TCP faz uma negociação RSA e troca um pacote AES+HMAC. 
public class NoAnel {
    public static final int TOTAL_NOS = 6;
    public static final int ARQUIVOS_POR_NO = 10;
    public static final int TOTAL_ARQUIVOS = TOTAL_NOS * ARQUIVOS_POR_NO;
    public static final int PORTA_BASE = 7000;
    public static final String MSG_ERRO_ENTRADA = "Erro na entrada de dados. Tente outra vez!";

    private static final Pattern FORMATO = Pattern.compile("^arquivo([1-9][0-9]{0,8})\\.ext$");
    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private final int id;
    private final int sucessor;
    private final int antecessor;
    private final Set<String> arquivos = new HashSet<>();
    private final Map<String, CompletableFuture<Mensagem>> pendentes = new ConcurrentHashMap<>();
    private final List<String> historico = Collections.synchronizedList(new ArrayList<>());
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    });
    private final Seguranca seguranca = new Seguranca();
    private ServerSocket servidor;

    public NoAnel(int id) {
        if (id < 0 || id >= TOTAL_NOS) throw new IllegalArgumentException("ID do no deve estar entre 0 e 5");
        this.id = id;
        this.sucessor = (id + 1) % TOTAL_NOS;
        this.antecessor = (id + TOTAL_NOS - 1) % TOTAL_NOS;
        for (int k = id * ARQUIVOS_POR_NO + 1; k <= (id + 1) * ARQUIVOS_POR_NO; k++) {
            arquivos.add("arquivo" + k + ".ext");
        }
    }

    public int getId() { return id; }

    public void iniciar() throws IOException {
        servidor = new ServerSocket(PORTA_BASE + id, 50, InetAddress.getLoopbackAddress());
        Thread aceitador = new Thread(this::aceitarConexoes, "P" + id + "-aceitador");
        aceitador.setDaemon(true);
        aceitador.start();
        log("No iniciado na porta " + (PORTA_BASE + id) + " | sucessor=P" + sucessor
                + " antecessor=P" + antecessor + " | arquivos "
                + (id * ARQUIVOS_POR_NO + 1) + " a " + ((id + 1) * ARQUIVOS_POR_NO));
    }

    public void parar() {
        try { if (servidor != null) servidor.close(); }
        catch (IOException ignorado) { /* encerrando */ }
        pool.shutdownNow();
    }

    private void aceitarConexoes() {
        while (servidor != null && !servidor.isClosed()) {
            try {
                Socket socket = servidor.accept();
                pool.execute(() -> tratarConexao(socket));
            } catch (IOException e) {
                if (servidor != null && !servidor.isClosed()) log("Erro ao aceitar conexao: " + e.getMessage());
            }
        }
    }

    private void tratarConexao(Socket socket) {
        try (Socket s = socket;
             ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream())) {
            out.flush();
            try (ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
                // O destinatário envia sua chave pública RSA para esta conexão.
                out.writeObject(seguranca.getChavePublica());
                out.flush();
                Object objeto = in.readObject();
                if (!(objeto instanceof PacoteSeguro)) {
                    log("Pacote invalido descartado: envelope seguro ausente");
                    return;
                }
                Mensagem mensagem;
                try {
                    mensagem = seguranca.abrir((PacoteSeguro) objeto);
                } catch (Seguranca.FalhaIntegridadeException e) {
                    log("FALHA DE AUTENTICACAO/INTEGRIDADE: HMAC invalido. Pacote descartado; nao sera encaminhado.");
                    return;
                }
                log("HMAC validado e mensagem AES descriptografada; recebeu " + mensagem.tipo
                        + "[" + mensagem.id + "] de forma segura");
                if (mensagem.tipo == Mensagem.Tipo.BUSCA) processarBusca(mensagem);
                else processarResposta(mensagem);
            }
        } catch (Exception e) {
            log("Mensagem invalida/erro de segurança descartado: " + e.getMessage());
        }
    }

    public CompletableFuture<Mensagem> buscar(String entrada) {
        String arquivo = entrada == null ? "" : entrada.trim();
        Matcher matcher = FORMATO.matcher(arquivo);
        int numero;
        try {
            if (!matcher.matches()) throw new IllegalArgumentException();
            numero = Integer.parseInt(matcher.group(1));
            if (numero < 1 || numero > TOTAL_ARQUIVOS) throw new IllegalArgumentException();
        } catch (IllegalArgumentException e) {
            System.out.println(MSG_ERRO_ENTRADA);
            historico.add(hora() + " [P" + id + "] Entrada rejeitada: \"" + arquivo + "\"");
            return null;
        }

        log("Usuario pediu busca de '" + arquivo + "'");
        CompletableFuture<Mensagem> futuro = new CompletableFuture<>();
        if (arquivos.contains(arquivo)) {
            Mensagem local = Mensagem.busca(id, arquivo);
            local.caminho.add(id);
            log("RESULTADO: '" + arquivo + "' e local (P" + id + "), nenhuma mensagem enviada");
            futuro.complete(local.comoResposta(id, true));
            return futuro;
        }

        Mensagem busca = Mensagem.busca(id, arquivo);
        busca.caminho.add(id);
        pendentes.put(busca.id, futuro);
        if (!enviar(busca, sucessor, false)) {
            pendentes.remove(busca.id);
            futuro.completeExceptionally(new IOException("sucessor P" + sucessor + " inacessivel"));
        }
        return futuro;
    }

    private void processarBusca(Mensagem m) {
        int remetente = m.caminho.isEmpty() ? -1 : m.caminho.get(m.caminho.size() - 1);
        log("RECEBEU BUSCA[" + m.id + "] '" + m.arquivo + "' de P" + remetente + " (origem P" + m.origem + ")");
        if (m.origem == id) {
            log("A busca deu a volta no anel: arquivo inexistente");
            concluir(m.comoResposta(-1, false));
            return;
        }
        m.caminho.add(id);
        if (arquivos.contains(m.arquivo)) {
            log("Possuo '" + m.arquivo + "'. Respondendo pelo antecessor P" + antecessor);
            enviar(m.comoResposta(id, true), antecessor, false);
        } else {
            log("Nao possuo '" + m.arquivo + "'. Repassando com novo pacote seguro ao sucessor P" + sucessor);
            enviar(m, sucessor, false);
        }
    }

    private void processarResposta(Mensagem m) {
        log("RECEBEU RESPOSTA[" + m.id + "] '" + m.arquivo + "'");
        if (m.origem == id) concluir(m);
        else {
            log("Nao sou a origem. Repassando resposta ao antecessor P" + antecessor);
            enviar(m, antecessor, false);
        }
    }

    private void concluir(Mensagem m) {
        if (m.encontrado) log("RESULTADO: '" + m.arquivo + "' encontrado em P" + m.responsavel
                + " | caminho da busca: " + m.caminhoTexto());
        else log("RESULTADO: '" + m.arquivo + "' NAO encontrado no anel");
        CompletableFuture<Mensagem> futuro = pendentes.remove(m.id);
        if (futuro != null) futuro.complete(m);
    }

    private boolean enviar(Mensagem m, int destino, boolean adulterar) {
        log("ENVIOU " + m.tipo + "[" + m.id + "] '" + m.arquivo + "' para P" + destino + " (RSA + AES + HMAC)");
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), PORTA_BASE + destino);
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {
            out.flush();
            Object chaveRecebida = in.readObject();
            if (!(chaveRecebida instanceof PublicKey)) throw new GeneralSecurityException("Chave pública inválida");
            PacoteSeguro pacote = seguranca.proteger(m, (PublicKey) chaveRecebida);
            if (adulterar) pacote = pacote.adulterar();
            out.writeObject(pacote);
            out.flush();
            return true;
        } catch (Exception e) {
            log("FALHA ao enviar para P" + destino + ": " + e.getMessage());
            return false;
        }
    }

    /** Caso de teste: envia de P4 para P5 um pacote cujo conteúdo foi adulterado após o HMAC. */
    public void testarPacoteAdulteradoParaSucessor() {
        Mensagem teste = Mensagem.busca(id, "arquivo45.ext");
        teste.caminho.add(id);
        enviar(teste, sucessor, true);
    }

    private static String hora() { return "[" + LocalTime.now().format(HORA) + "]"; }

    private void log(String texto) {
        String linha = hora() + " [P" + id + "] " + texto;
        historico.add(linha);
        System.out.println(linha);
    }

    public void imprimirHistorico() {
        System.out.println("---- Log de P" + id + " (" + historico.size() + " entradas) ----");
        synchronized (historico) { for (String linha : historico) System.out.println(linha); }
    }
}
