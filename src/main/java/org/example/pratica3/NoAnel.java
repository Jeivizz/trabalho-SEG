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


public class NoAnel {
    public static final int TOTAL_NOS = 6;
    public static final int ARQUIVOS_POR_NO = 10;
    public static final int TOTAL_ARQUIVOS = TOTAL_NOS * ARQUIVOS_POR_NO; // 60
    public static final int PORTA_BASE = 7000; // P0=7000, P1=7001...
    public static final String MSG_ERRO_ENTRADA = "Erro na entrada de dados. Tente outra vez!";

    // Regex que valida "arquivoN.ext" N de 1 a 9 dígitos, sem zero à esquerda
    private static final Pattern FORMATO = Pattern.compile("^arquivo([1-9][0-9]{0,8})\\.ext$");
    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private final int id;
    private final int sucessor;    // (id+1) % 6
    private final int antecessor;  // (id+5) % 6
    private final Set<String> arquivos = new HashSet<>(); // arquivos locais
    private final Map<String, CompletableFuture<Mensagem>> pendentes = new ConcurrentHashMap<>();
    private final List<String> historico = Collections.synchronizedList(new ArrayList<>());
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    });
    private final Seguranca seguranca = new Seguranca(); // par RSA deste nó
    private ServerSocket servidor;

    public NoAnel(int id) {
        if (id < 0 || id >= TOTAL_NOS) throw new IllegalArgumentException("ID do no deve estar entre 0 e 5");
        this.id = id;
        this.sucessor = (id + 1) % TOTAL_NOS;
        this.antecessor = (id + TOTAL_NOS - 1) % TOTAL_NOS;
        // Distribuição: P0 tem 1..10, P1 tem 11..20, ...
        for (int k = id * ARQUIVOS_POR_NO + 1; k <= (id + 1) * ARQUIVOS_POR_NO; k++) {
            arquivos.add("arquivo" + k + ".ext");
        }
    }

    public int getId() { return id; }

    // Sobe o ServerSocket do nó e inicia a thread aceitadora
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
        pool.shutdownNow(); // encerra threads do pool
    }

    // Loop da thread aceitadora: cada conexão vira uma tarefa no pool
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

    // Trata UMA conexão: envia pubkey, recebe PacoteSeguro, valida HMAC, decifra e processa.
    private void tratarConexao(Socket socket) {
        try (Socket s = socket;
             ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream())) {
            // flush imediato para evitar deadlock na negociação do header do ObjectStream
            out.flush();
            try (ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
                //  O DESTINATÁRIO envia sua chave pública RSA
                out.writeObject(seguranca.getChavePublica());
                out.flush();

                //  Lê o envelope seguro
                Object objeto = in.readObject();
                if (!(objeto instanceof PacoteSeguro)) {
                    log("Pacote invalido descartado: envelope seguro ausente");
                    return;
                }

                //  Abre o envelope: decifra chaves com RSA, valida HMAC, decifra AES
                Mensagem mensagem;
                try {
                    mensagem = seguranca.abrir((PacoteSeguro) objeto);
                } catch (Seguranca.FalhaIntegridadeException e) {
                    // CASO 3: HMAC inválido: descarta e NÃO repassa 
                    log("FALHA DE AUTENTICACAO/INTEGRIDADE: HMAC invalido. Pacote descartado; nao sera encaminhado.");
                    return;
                }
                log("HMAC validado e mensagem AES descriptografada; recebeu " + mensagem.tipo
                        + "[" + mensagem.id + "] de forma segura");

                //  Processa conforme o tipo
                if (mensagem.tipo == Mensagem.Tipo.BUSCA) processarBusca(mensagem);
                else processarResposta(mensagem);
            }
        } catch (Exception e) {
            // Qualquer outra falha socket, serialização, RSA, descarta
            log("Mensagem invalida/erro de segurança descartado: " + e.getMessage());
        }
    }

    // Inicia uma busca a partir deste nó chamado pelo console
    public CompletableFuture<Mensagem> buscar(String entrada) {
        String arquivo = entrada == null ? "" : entrada.trim();
        Matcher matcher = FORMATO.matcher(arquivo);
        int numero;
        try {
            // Validação sintática regex e semântica (faixa 1..60)
            if (!matcher.matches()) throw new IllegalArgumentException();
            numero = Integer.parseInt(matcher.group(1));
            if (numero < 1 || numero > TOTAL_ARQUIVOS) throw new IllegalArgumentException();
        } catch (IllegalArgumentException e) {
            // CASO 2: entrada inválida -> rejeita SEM abrir conexão nem propagar 
            System.out.println(MSG_ERRO_ENTRADA);
            historico.add(hora() + " [P" + id + "] Entrada rejeitada: \"" + arquivo + "\"");
            return null;
        }

        log("Usuario pediu busca de '" + arquivo + "'");
        CompletableFuture<Mensagem> futuro = new CompletableFuture<>();

        // Otimização: se o arquivo é local, nem envia
        if (arquivos.contains(arquivo)) {
            Mensagem local = Mensagem.busca(id, arquivo);
            local.caminho.add(id);
            log("RESULTADO: '" + arquivo + "' e local (P" + id + "), nenhuma mensagem enviada");
            futuro.complete(local.comoResposta(id, true));
            return futuro;
        }

        // Cria BUSCA, registra futuro pendente e envia ao sucessor cifrado
        Mensagem busca = Mensagem.busca(id, arquivo);
        busca.caminho.add(id);
        pendentes.put(busca.id, futuro);
        if (!enviar(busca, sucessor, false)) {
            pendentes.remove(busca.id);
            futuro.completeExceptionally(new IOException("sucessor P" + sucessor + " inacessivel"));
        }
        return futuro;
    }

    // Trata BUSCA recebida de outro nó
    private void processarBusca(Mensagem m) {
        int remetente = m.caminho.isEmpty() ? -1 : m.caminho.get(m.caminho.size() - 1);
        log("RECEBEU BUSCA[" + m.id + "] '" + m.arquivo + "' de P" + remetente + " (origem P" + m.origem + ")");

        // Se a busca voltou a origem: arquivo não existe no anel
        // evita loop infinito
        if (m.origem == id) {
            log("A busca deu a volta no anel: arquivo inexistente");
            concluir(m.comoResposta(-1, false));
            return;
        }

        m.caminho.add(id); // registra passagem
        if (arquivos.contains(m.arquivo)) {
            // Possui: responde pelo antecessor 
            log("Possuo '" + m.arquivo + "'. Respondendo pelo antecessor P" + antecessor);
            enviar(m.comoResposta(id, true), antecessor, false);
        } else {
            // Não possui: repassa ao sucessor com NOVO pacote seguro
            log("Nao possuo '" + m.arquivo + "'. Repassando com novo pacote seguro ao sucessor P" + sucessor);
            enviar(m, sucessor, false);
        }
    }

    // Trata RESPOSTA recebida (volta pelo antecessor até a origem)
    private void processarResposta(Mensagem m) {
        log("RECEBEU RESPOSTA[" + m.id + "] '" + m.arquivo + "'");
        if (m.origem == id) concluir(m); // sou a origem: finaliza
        else {
            // Não sou a origem: repasso ao antecessor
            log("Nao sou a origem. Repassando resposta ao antecessor P" + antecessor);
            enviar(m, antecessor, false);
        }
    }

    // Finaliza: loga resultado/caminho e completa o futuro pendente
    private void concluir(Mensagem m) {
        if (m.encontrado) log("RESULTADO: '" + m.arquivo + "' encontrado em P" + m.responsavel
                + " | caminho da busca: " + m.caminhoTexto());
        else log("RESULTADO: '" + m.arquivo + "' NAO encontrado no anel");
        CompletableFuture<Mensagem> futuro = pendentes.remove(m.id);
        if (futuro != null) futuro.complete(m);
    }

    // Envia Mensagem para outro nó via TCP, usando criptografia híbrida SALTO A SALTO.
    // O parâmetro 'adulterar' é um GANCHO DE TESTE (Caso 3): altera 1 bit do cifrado.
    private boolean enviar(Mensagem m, int destino, boolean adulterar) {
        log("ENVIOU " + m.tipo + "[" + m.id + "] '" + m.arquivo + "' para P" + destino + " (RSA + AES + HMAC)");
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), PORTA_BASE + destino);
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {
            out.flush(); // mesmo detalhe de deadlock do lado servidor
            //  Recebe a pubkey RSA do DESTINO
            Object chaveRecebida = in.readObject();
            if (!(chaveRecebida instanceof PublicKey)) throw new GeneralSecurityException("Chave pública inválida");
            //  Protege a Mensagem para o destino (AES efêmero + RSA-OAEP + HMAC)
            PacoteSeguro pacote = seguranca.proteger(m, (PublicKey) chaveRecebida);
            if (adulterar) pacote = pacote.adulterar(); // só no teste do Caso 3
            //  Envia o envelope
            out.writeObject(pacote);
            out.flush();
            return true;
        } catch (Exception e) {
            log("FALHA ao enviar para P" + destino + ": " + e.getMessage());
            return false;
        }
    }

    // Caso de teste: envia de P4 para P5 um pacote cujo conteúdo foi adulterado após o HMAC. 
    public void testarPacoteAdulteradoParaSucessor() {
        Mensagem teste = Mensagem.busca(id, "arquivo45.ext");
        teste.caminho.add(id);
        enviar(teste, sucessor, true); // adulterar = true
    }

    private static String hora() { return "[" + LocalTime.now().format(HORA) + "]"; }

    // Log: imprime e guarda no histórico
    private void log(String texto) {
        String linha = hora() + " [P" + id + "] " + texto;
        historico.add(linha);
        System.out.println(linha);
    }

    public void imprimirHistorico() {
        System.out.println("<><><> Log de P" + id + " (" + historico.size() + " entradas) <><><>");
        synchronized (historico) { for (String linha : historico) System.out.println(linha); }
    }
}