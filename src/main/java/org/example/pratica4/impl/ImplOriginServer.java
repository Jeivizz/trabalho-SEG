package org.example.pratica4.impl;

import org.example.pratica4.OriginServer;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class ImplOriginServer implements Runnable {
    public Socket socketCliente;

    public ImplOriginServer(Socket cliente) {
        this.socketCliente = cliente;
    }

    @Override
    public void run() {
        // Fecha scanner/stream sozinho no fim do try
        try (Scanner entrada = new Scanner(socketCliente.getInputStream());
             PrintStream saida = new PrintStream(socketCliente.getOutputStream())) {

            if (!entrada.hasNextLine()) return; // Caso não tenha nada na entrada para ler

            String requisicao = entrada.nextLine();
            OriginServer.registrar("[Origin] recebido: " + requisicao);

            // Ex: "GET /arquivo20.ext"
            if (requisicao.startsWith("GET ")) {
                String nome = requisicao.substring(4).trim();

                if (nome.startsWith("/")) nome = nome.substring(1); // tira '/'. para evistar problemas na busca

                Path caminho = OriginServer.DIR_DADOS.resolve(nome); //caminho do arquivo

                // Confere se o caminho está dentro da pasta correta, para evitar consultas externas
                if (!caminho.normalize().startsWith(OriginServer.DIR_DADOS.normalize())) {
                    saida.println("404 Not Found");
                    OriginServer.registrar("[Origin] bloqueado (fora da pasta): " + nome);
                    return;
                }

                if (Files.exists(caminho)) { // Caso o arquivo exista

                    // Leitura no Disco
                    String conteudo = Files.readString(caminho);
                    saida.println("200 OK");
                    saida.println("Length: " + conteudo.length());
                    saida.println(conteudo);
                    OriginServer.registrar("[Origin] enviado: " + nome + " (" + conteudo.length() + " bytes)");
                } else {
                    saida.println("404 Not Found");
                    OriginServer.registrar("[Origin] 404 pra " + nome);
                }
            }
        } catch (IOException e) {
            // se o Edge cair, Origin continua
            System.out.println("[Origin] conexao encerrada com erro: " + e.getMessage());
        }
    }
}