package org.example.pratica4.impl;

import org.example.pratica4.ClienteCDN;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;

public class ImplClienteCDN implements Runnable {
    String edgeAlvo;
    String nomeArquivo;

    // Construtor de ImplClienteCDN
    public ImplClienteCDN(String edge, String arquivo) {
        this.edgeAlvo = edge;
        this.nomeArquivo = arquivo;
    }

    @Override
    public void run() {
        // Divide ip e porta
        String[] partes = edgeAlvo.split(":");
        String ip = partes[0];
        int porta = Integer.parseInt(partes[1]);

        // Guarda o tempo de início para calcular o tempo de execução
        long inicio = System.currentTimeMillis();

        try (Socket socket = new Socket(ip, porta);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            // Carrega a chave pública
            PublicKey pubEdge = SegurancaUtils.carregarPublica("edge_" + porta);
            var ctx = SegurancaUtils.criarMensagemSegura("GET /" + nomeArquivo, pubEdge);
            out.println(ctx.pacote);

            // Recebe a resposta do Edge
            String resp = in.readLine();
            if (resp == null) {
                System.out.println("[Cliente] sem resposta do Edge");
                return;
            }

            // Decifra a resposta
            String texto = SegurancaUtils.decifrarResposta(resp, ctx.aesKey, ctx.hmacKey);

            // Calcula o tempo
            long tempo = System.currentTimeMillis() - inicio;
            System.out.println("[Cliente] HMAC da resposta validado em " + tempo + " ms:");
            System.out.println(texto);
            ClienteCDN.logs.add("[Cliente] " + nomeArquivo + " -> " + tempo + " ms");

        } catch (Exception e) {
            System.out.println("[Cliente] erro TCP com " + edgeAlvo + ": " + e.getMessage());
        }
    }
}