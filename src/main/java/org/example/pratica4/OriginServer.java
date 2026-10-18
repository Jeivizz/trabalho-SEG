package org.example.pratica4;

import org.example.pratica4.impl.ImplOriginServer;

import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class OriginServer {
    int porta;
    public static List<String> logs = new ArrayList<>();

    // cada Edge escuta numa porta. Origin vai ler as portas para fazer a Invalidação
    private static final int[] PORTAS_EDGES = {8001, 8002, 8003};

    // Caminho para leitura diretamente no disco
    public static final Path DIR_DADOS = Paths.get("origin_data");

    // Ao instanciar OriginServer, automaticamente vai rodar os métodos de arquivos e validação
    public OriginServer(int porta) {
        this.porta = porta;
        criarArquivosSeNaoExistirem();
        iniciarConsoleInvalidacao();
        this.rodar();
    }


    private static void criarArquivosSeNaoExistirem() {
        try {
            Files.createDirectories(DIR_DADOS);
            for (int i = 1; i <= 1000; i++) {
                Path p = DIR_DADOS.resolve("arquivo" + i + ".ext");
                // Sempre escreve versao 1, mesmo que exista. (Apenas para evitar erro caso execute de novo)

                Files.writeString(p, "Conteudo bruto mestre do arquivo" + i
                        + ".ext versao 1 armazenado no Origin Server.");
            }
            System.out.println("[Origin] 1000 arquivos resetados para versao 1 em "
                    + DIR_DADOS.toAbsolutePath());
        } catch (IOException e) {
            throw new RuntimeException("Nao consegui preparar a pasta de dados", e);
        }
    }

    // fica lendo o teclado pra simular a alteracao de conteudo no origin.
    private void iniciarConsoleInvalidacao() {
        Thread t = new Thread(() -> {
            Scanner teclado = new Scanner(System.in);
            System.out.println("Origem pronta. Digite o nome de um arquivo (ex: arquivo30.ext)");
            System.out.println("pra atualizar o conteudo e invalidar nos Edges.");

            while (teclado.hasNextLine()) {
                String arquivo = teclado.nextLine().trim();
                if (arquivo.isEmpty()) continue;

                // atualiza o arquivo no disco pra versao 2. Sem isso o cache miss ia devolver o mesmo texto
                String novo = "Conteudo bruto mestre do " + arquivo
                        + " versao 2 (ATUALIZADO) armazenado no Origin Server.";
                try {
                    Files.writeString(DIR_DADOS.resolve(arquivo), novo);
                    System.out.println("[Origin] " + arquivo + " atualizado no disco (versao 2).");
                } catch (IOException e) {
                    System.out.println("[Origin] Falha ao atualizar " + arquivo + ": " + e.getMessage());
                }

                // manda INVALIDATE pra cada Edge (protocolo com barra, igual ao PDF)
                String comando = "INVALIDATE /" + arquivo;
                for (int portaEdge : PORTAS_EDGES) {
                    try (Socket s = new Socket("127.0.0.1", portaEdge);
                         PrintStream out = new PrintStream(s.getOutputStream())) {
                        out.println(comando);
                        registrar("[Origin] enviado: " + comando + " -> Edge " + portaEdge);
                    } catch (IOException e) {
                        System.out.println("[Origin] Edge " + portaEdge + " nao respondeu.");
                    }
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private void rodar() {
        try (ServerSocket servidor = new ServerSocket(porta)) {
            System.out.println("Origin Server (TCP) na porta [" + porta + "]");
            while (true) {
                Socket cliente = servidor.accept();
                new Thread(new ImplOriginServer(cliente)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Função para não repetir synchronized
    public static void registrar(String linha) {
        synchronized (logs) {
            logs.add(linha);
        }
        System.out.println(linha);
    }

    public static void main(String[] args) {
        new OriginServer(8000);
    }
}