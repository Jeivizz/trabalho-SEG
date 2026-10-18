package org.example.pratica4.impl;

import org.example.pratica4.ClienteCDN;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.Scanner;

public class ImplClienteCDN implements Runnable {
    String edgeAlvo;
    String nomeArquivo;

    public ImplClienteCDN(String edge, String arquivo) {
        this.edgeAlvo = edge;
        this.nomeArquivo = arquivo;
    }

    @Override
    public void run() {
        String[] partes = edgeAlvo.split(":");
        String ip = partes[0];
        int porta = Integer.parseInt(partes[1]);

        long inicio = System.currentTimeMillis();

        try (Socket socket = new Socket(ip, porta);
             PrintStream saida = new PrintStream(socket.getOutputStream());
             Scanner entrada = new Scanner(socket.getInputStream())) {

            // protocolo combinado com o Edge: "GET /nomearquivo"
            saida.println("GET /" + nomeArquivo);

            StringBuilder sb = new StringBuilder();
            while (entrada.hasNextLine()) {
                sb.append(entrada.nextLine()).append("\n");
            }

            long tempo = System.currentTimeMillis() - inicio;
            System.out.println("[Cliente] resposta do Edge " + edgeAlvo + " em " + tempo + " ms:");
            System.out.println(sb.toString().trim());

            synchronized (ClienteCDN.logs) {
                ClienteCDN.logs.add("[Cliente] " + edgeAlvo + " (" + tempo + "ms): "
                        + sb.toString().replace("\n", " | "));
            }

        } catch (IOException e) {
            System.out.println("[Cliente] erro TCP com " + edgeAlvo + ": " + e.getMessage());
        }
    }
}