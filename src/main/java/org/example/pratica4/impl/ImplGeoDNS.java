package org.example.pratica4.impl;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class ImplGeoDNS implements Runnable {
    public DatagramSocket socketServidor;
    public DatagramPacket pacote;
    public KeyPair keyPair;
    public static List<String> logs = new ArrayList<>();

    private static final String[] EDGES = {"127.0.0.1:8001", "127.0.0.1:8002", "127.0.0.1:8003"};
    private static int rr = 0;

    // Construtor de ImplGeoDNS
    public ImplGeoDNS(DatagramSocket s, DatagramPacket p, KeyPair kp) {
        this.socketServidor = s;
        this.pacote = p;
        this.keyPair = kp;
    }

    @Override
    public void run() {
        try {
            // corta pro tamanho real do datagrama (getData devolve o buffer inteiro)
            byte[] corte = new byte[pacote.getLength()];
            System.arraycopy(pacote.getData(), 0, corte, 0, pacote.getLength());
            String pacoteStr = new String(corte, "UTF-8");

            SegurancaUtils.MensagemDecifrada msg;
            try {
                msg = SegurancaUtils.decriptarEValidarMensagem(pacoteStr, keyPair.getPrivate());
            } catch (Exception e) { // Problema com INtegridade (HMAC)
                registrar("[GeoDNS] falha de integridade - descartando");
                return;
            }
            // Integridade Ok, decifragem OK
            registrar("[GeoDNS] HMAC validado + payload decifrado: " + msg.payload);

            // extrai Local=XX
            String local = "";
            int idx = msg.payload.indexOf("Local=");
            if (idx >= 0) {
                local = msg.payload.substring(idx + 6).trim().split("\\s+")[0].toUpperCase();
            }

            String edge;
            // Define o local
            switch (local) {
                case "BR": edge = EDGES[0]; break;
                case "US": edge = EDGES[1]; break;
                case "EU": edge = EDGES[2]; break;
                default:
                    // Synchronized para evitar trocar os valores entre as threads. RoundRobin
                    synchronized (EDGES) { edge = EDGES[rr]; rr = (rr + 1) % EDGES.length; }
                    registrar("[GeoDNS] local desconhecido, round robin: " + edge);
            }

            // resposta cifrada usando as chaves da requisicao
            byte[] resp = SegurancaUtils.criarRespostaSegura(edge, msg.aesKey, msg.hmacKey).getBytes("UTF-8");
            socketServidor.send(new DatagramPacket(resp, resp.length, pacote.getAddress(), pacote.getPort()));
            registrar("[GeoDNS] respondido cifrado: " + edge);

        } catch (Exception e) {
            System.out.println("[GeoDNS] erro: " + e.getMessage());
        }
    }

    // Função auxiliar para registrar log
    private void registrar(String linha) {
        synchronized (logs) { logs.add(linha); }
        System.out.println(linha);
    }
}