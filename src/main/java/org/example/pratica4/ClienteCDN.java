package org.example.pratica4;

import org.example.pratica4.impl.ImplClienteCDN;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;

public class ClienteCDN {
    String ipGeoDNS;
    int portaGeoDNS;
    public static List<String> logs = new ArrayList<>();

    public ClienteCDN(String ip, int porta) {
        this.ipGeoDNS = ip;
        this.portaGeoDNS = porta;
        this.rodar();
    }

    private void rodar() {
        System.out.println("=== TESTES DA CDN ===");

        // caso 1: mede o tempo pra provar que o HIT eh mais rapido que o MISS
        System.out.println("\n[1] Cache MISS vs HIT");
        long t1 = System.currentTimeMillis();
        solicitarArquivo("arquivo20.ext");
        long t2 = System.currentTimeMillis();
        solicitarArquivo("arquivo20.ext");
        long t3 = System.currentTimeMillis();

        long missMs = t2 - t1;
        long hitMs = t3 - t2;
        System.out.println("---------------------------------------------");
        System.out.println("1a requisicao (esperado MISS): " + missMs + " ms");
        System.out.println("2a requisicao (esperado HIT) : " + hitMs + " ms");
        if (hitMs < missMs) {
            System.out.println("=> HIT foi " + (missMs - hitMs) + " ms mais rapido");
        } else {
            System.out.println("=> tempos muito proximos (normal em localhost, olhar os logs do Origin)");
        }
        System.out.println("---------------------------------------------");

        // caso 2: espera passar o TTL de 10s e forca expiracao
        System.out.println("\n[2] Expiracao por TTL");
        System.out.println("Aguardando 11s pra expirar...");
        try { Thread.sleep(11_000); } catch (InterruptedException ignored) {}
        solicitarArquivo("arquivo20.ext");

        // caso 3: cacheia uma vez, o usuario invalida no console do Origin,
        // e depois requisita de novo pra ver o MISS forcado
        System.out.println("\n[3] Invalidacao ativa");
        System.out.println("Buscando arquivo30.ext pra cachear...");
        solicitarArquivo("arquivo30.ext");

        System.out.println("Agora va no console do Origin e digite: arquivo30.ext");
        System.out.println("Depois volte aqui e aperte ENTER pra buscar de novo.");
        try { System.in.read(); } catch (IOException ignored) {}

        solicitarArquivo("arquivo30.ext");
    }

    private void solicitarArquivo(String nomeArquivo) {
        // primeiro pergunta pro GeoDNS onde ta o Edge
        try (DatagramSocket udp = new DatagramSocket()) {
            udp.setSoTimeout(5000);

            String payload = "Onde baixo o arquivo " + nomeArquivo + "? Local=BR";
            byte[] msg = payload.getBytes();
            InetAddress host = InetAddress.getByName(ipGeoDNS);
            udp.send(new DatagramPacket(msg, msg.length, host, portaGeoDNS));
            registrar("[Cliente] enviado UDP: " + payload);

            byte[] buf = new byte[1024];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            udp.receive(resp);
            String edge = new String(resp.getData(), 0, resp.getLength()).trim();
            registrar("[Cliente] GeoDNS respondeu: " + edge);

            // agora faz o GET via TCP direto no Edge
            Thread t = new Thread(new ImplClienteCDN(edge, nomeArquivo));
            t.start();
            t.join();

        } catch (SocketTimeoutException e) {
            System.out.println("[Cliente] GeoDNS nao respondeu em 5s");
        } catch (Exception e) {
            System.out.println("[Cliente] erro: " + e.getMessage());
        }
    }

    private void registrar(String linha) {
        synchronized (logs) {
            logs.add(linha);
        }
        System.out.println(linha);
    }

    public static void main(String[] args) {
        new ClienteCDN("127.0.0.1", 5354);
    }
}