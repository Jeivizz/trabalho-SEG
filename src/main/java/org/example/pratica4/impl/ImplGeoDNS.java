package org.example.pratica4.impl;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.ArrayList;
import java.util.List;

public class ImplGeoDNS implements Runnable {
    public DatagramSocket socketServidor;
    public DatagramPacket pacote;

    public static List<String> logs = new ArrayList<>();

    // Edges disponiveis. Fixo por conveniencia para o trabalho
    private static final String[] EDGES = {"127.0.0.1:8001", "127.0.0.1:8002", "127.0.0.1:8003"};

    private static int rr = 0; // Para quando não der para decidir pela localização

    public ImplGeoDNS(DatagramSocket socket, DatagramPacket pacote) {
        this.socketServidor = socket;
        this.pacote = pacote;
    }

    @Override
    public void run() {
        try {
            String texto = new String(pacote.getData(), 0, pacote.getLength());
            registrar("[GeoDNS] recebido: " + texto + " de " + pacote.getAddress().getHostAddress());

            // extrai Local=XX do payload. se nao achar, cai no round robin
            String local = extrairLocal(texto);
            String edge;

            switch (local) {
                case "BR": edge = EDGES[0]; break;
                case "US": edge = EDGES[1]; break;
                case "EU": edge = EDGES[2]; break;
                default:
                    synchronized (EDGES) {
                        edge = EDGES[rr];
                        rr = (rr + 1) % EDGES.length;
                    }
                    registrar("[GeoDNS] Local desconhecido, round robin escolheu " + edge);
            }

            byte[] dados = edge.getBytes();
            DatagramPacket resposta = new DatagramPacket(
                    dados, dados.length, pacote.getAddress(), pacote.getPort());
            socketServidor.send(resposta);
            registrar("[GeoDNS] respondido: " + edge);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // procura "Local=XX" no texto. retorna vazio se não achar
    private String extrairLocal(String texto) {
        int i = texto.indexOf("Local=");
        if (i < 0) return "";
        String resto = texto.substring(i + 6).trim();
        // pega a primeira palavra do texto
        int espaco = resto.indexOf(' ');
        return (espaco >= 0 ? resto.substring(0, espaco) : resto).toUpperCase();
    }

    private void registrar(String linha) {
        synchronized (logs) {
            logs.add(linha);
        }
        System.out.println(linha);
    }
}