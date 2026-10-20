package org.example.pratica4.impl;

import org.example.pratica4.OriginServer;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;

public class ImplOriginServer implements Runnable {
    public Socket socketCliente;

    public ImplOriginServer(Socket cliente) { this.socketCliente = cliente; }

    @Override
    public void run() {
        // Cada linha é uma mensagem cifrada. readLine/println
        try (Socket s = socketCliente;
             BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
             PrintWriter out = new PrintWriter(s.getOutputStream(), true)) {

            String pacote = in.readLine();
            if (pacote == null || pacote.isEmpty()) return;

            SegurancaUtils.MensagemDecifrada msg;
            try {
                msg = SegurancaUtils.decriptarEValidarMensagem(pacote, OriginServer.KEYPAIR.getPrivate());
            } catch (Exception e) {
                // HMAC errado, RSA invalido, pacote mal formado
                OriginServer.registrar("[Origin] falha de integridade - descartando");
                return;
            }

            OriginServer.registrar("[Origin] HMAC validado + payload decifrado: " + msg.payload);

            String resposta;
            if (msg.payload.startsWith("GET ")) {
                String nome = msg.payload.substring(4).trim();
                if (nome.startsWith("/")) nome = nome.substring(1);

                // Evita consultas em arquivos que não sejam no modelo "arquivoXX.ext
                if (!nome.matches("arquivo\\d+\\.ext")) {
                    resposta = "403 Forbidden";
                } else {
                    // Evita consultas em outros espaços de armazenamento
                    Path caminho = OriginServer.DIR_DADOS.resolve(nome).normalize();
                    if (!caminho.startsWith(OriginServer.DIR_DADOS.normalize())) {
                        resposta = "403 Forbidden";
                    } else if (Files.exists(caminho)) { // Verifica se o arquivo existe no caminho passado
                        String conteudo = Files.readString(caminho); // Pega o conteúdo do arquivo
                        resposta = "200 OK\nLength: " + conteudo.length() + "\n" + conteudo;
                    } else {
                        // Não encontrado
                        resposta = "404 Not Found";
                    }
                }
            } else {
                resposta = "400 Bad Request";
            }

            out.println(SegurancaUtils.criarRespostaSegura(resposta, msg.aesKey, msg.hmacKey));
            OriginServer.registrar("[Origin] resposta cifrada enviada");

        } catch (Exception e) {
            System.out.println("[Origin] erro: " + e.getMessage());
        }
    }
}