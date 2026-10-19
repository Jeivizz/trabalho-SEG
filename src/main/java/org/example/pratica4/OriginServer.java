package org.example.pratica4;

import org.example.pratica4.impl.ImplOriginServer;
import org.example.pratica4.impl.SegurancaUtils;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class OriginServer {
    int porta;
    public static List<String> logs = new ArrayList<>();
    private static final int[] PORTAS_EDGES = {8001, 8002, 8003};
    public static final Path DIR_DADOS = Paths.get("origin_data");
    public static KeyPair KEYPAIR;

    // Construtor OriginServer e roda seus métodos automaticamente ao ser instanciado
    public OriginServer(int porta) throws Exception {
        this.porta = porta;
        KEYPAIR = SegurancaUtils.carregarOuCriarKeyPair("origin");
        prepararArquivos();
        iniciarConsoleInvalidacao();
        rodar();
    }

    // Gera os arquivos no disco. Reseta em toda execução para evitar erro na simulação
    private static void prepararArquivos() {
        try {
            Files.createDirectories(DIR_DADOS);
            for (int i = 1; i <= 1000; i++) {
                Files.writeString(DIR_DADOS.resolve("arquivo" + i + ".ext"),
                        "Conteudo bruto mestre do arquivo" + i
                                + ".ext versao 1 armazenado no Origin Server.");
            }
            System.out.println("[Origin] 1000 arquivos resetados em " + DIR_DADOS.toAbsolutePath());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // console no terminal de OriginServer para o caso de INVALIDATE (teste: arquivo30.ext)
    private void iniciarConsoleInvalidacao() {
        Thread t = new Thread(() -> {
            Scanner teclado = new Scanner(System.in);
            System.out.println("[Origin] digite arquivo30.ext (ou outro) pra atualizar + invalidar:");
            while (teclado.hasNextLine()) {
                String arq = teclado.nextLine().trim();
                if (arq.isEmpty()) continue;
                try {
                    Files.writeString(DIR_DADOS.resolve(arq),
                            "Conteudo bruto mestre do " + arq
                                    + " versao 2 (ATUALIZADO) armazenado no Origin Server.");
                    registrar("[Origin] atualizado no disco: " + arq);
                } catch (IOException e) {
                    System.out.println("[Origin] falha ao atualizar " + arq);
                    continue;
                }

                // Envia a mensagem segura do INVALIDATE aos EdgeServers
                String comando = "INVALIDATE /" + arq;
                for (int p : PORTAS_EDGES) {
                    // Tenta com todos os EdgeServers
                    try (Socket s = new Socket("127.0.0.1", p);
                         PrintWriter out = new PrintWriter(s.getOutputStream(), true)) {
                        PublicKey pubEdge = SegurancaUtils.carregarPublica("edge_" + p);
                        var ctx = SegurancaUtils.criarMensagemSegura(comando, pubEdge);
                        out.println(ctx.pacote);
                        registrar("[Origin] INVALIDATE cifrado enviado ao Edge " + p);
                    } catch (Exception e) {
                        // Erro de Edge server Indisponível
                        System.out.println("[Origin] Edge " + p + " indisponivel");
                    }
                }
            }
        });
        // Vai rodar em segundo plano enquanto houver outras threads rodando
        t.setDaemon(true);
        t.start();
    }

    // Inicializa o funcionamento assim que o objeto OriginServer é instanciado
    private void rodar() {
        try (ServerSocket servidor = new ServerSocket(porta)) {
            System.out.println("[Origin] TCP escutando na porta " + porta);
            while (true) {
                Socket cliente = servidor.accept();
                new Thread(new ImplOriginServer(cliente)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Funcção auxiliar para registrar o log
    public static void registrar(String linha) {
        synchronized (logs) { logs.add(linha); }
        System.out.println(linha);
    }

    public static void main(String[] args) throws Exception {
        new OriginServer(8000);
    }
}