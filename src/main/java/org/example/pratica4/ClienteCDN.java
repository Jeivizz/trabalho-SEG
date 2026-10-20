package org.example.pratica4;

import org.example.pratica4.impl.ImplClienteCDN;
import org.example.pratica4.impl.SegurancaUtils;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ClienteCDN {
    String ipGeoDNS;
    int portaGeoDNS;
    public static List<String> logs = new ArrayList<>();

    // Construtor ClienteCDN e roda seu método ao ser instanciado
    public ClienteCDN(String ip, int porta) {
        this.ipGeoDNS = ip;
        this.portaGeoDNS = porta;
        this.rodar();
    }

    // testes pedidos na atividade - Inicia o funcionamento assim que o objeto é instanciado
    private void rodar() {
        System.out.println("========= TESTES DA CDN (SEG) =========");

        // Caso 1: HIT vs MISS com tempo
        System.out.println("\n[Caso 1] HIT vs MISS em canal cifrado");
        long t1 = System.currentTimeMillis();
        solicitarArquivo("arquivo20.ext");
        long t2 = System.currentTimeMillis();
        solicitarArquivo("arquivo20.ext");
        long t3 = System.currentTimeMillis();
        System.out.println("---------------------------------------------");
        System.out.println("MISS: " + (t2 - t1) + " ms / HIT: " + (t3 - t2) + " ms");
        System.out.println("---------------------------------------------");

        // Caso 2a: TTL
        System.out.println("\n[Caso 2a] Expiracao por TTL (11s)");
        try { Thread.sleep(11_000); } catch (InterruptedException ignored) {}
        solicitarArquivo("arquivo20.ext");

        // Caso 2b: invalidacao ativa
        System.out.println("\n[Caso 2b] Invalidacao ativa");
        solicitarArquivo("arquivo30.ext");
        System.out.println(">> Digite 'arquivo30.ext' no console do Origin e aperte ENTER aqui.");
        try { System.in.read(); } catch (Exception ignored) {}
        solicitarArquivo("arquivo30.ext");

        // Caso 3a: nome invalido
        System.out.println("\n[Caso 3a] Nome invalido");
        solicitarArquivo("arquivoXYZ.ext");

        // Caso 3b: HMAC corrompido
        System.out.println("\n[Caso 3b] HMAC corrompido");
        testarHMACCorrompido("arquivo20.ext");

    }

    // consulta cifrada ao GeoDNS
    private String descobrirEdge(String nomeArquivo) throws Exception {
        PublicKey pubGeo = SegurancaUtils.carregarPublica("geodns");
        var ctx = SegurancaUtils.criarMensagemSegura(
                "Onde baixo o arquivo " + nomeArquivo + "? Local=BR", pubGeo);

        try (DatagramSocket udp = new DatagramSocket()) {
            udp.setSoTimeout(5000);
            InetAddress host = InetAddress.getByName(ipGeoDNS);
            byte[] pac = ctx.pacote.getBytes("UTF-8");
            udp.send(new DatagramPacket(pac, pac.length, host, portaGeoDNS));
            registrar("[Cliente] enviado UDP cifrado: " + nomeArquivo);

            byte[] buf = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            udp.receive(resp);

            String respStr = new String(resp.getData(), 0, resp.getLength(), "UTF-8");
            String edge = SegurancaUtils.decifrarResposta(respStr, ctx.aesKey, ctx.hmacKey);
            registrar("[Cliente] HMAC do GeoDNS validado -> " + edge);
            return edge;
        }
    }

    // Descobre o EdgeServer e define a Thread
    private void solicitarArquivo(String nome) {
        try {
            String edge = descobrirEdge(nome);
            Thread t = new Thread(new ImplClienteCDN(edge, nome));
            t.start();
            t.join();
        } catch (Exception e) {
            System.out.println("[Cliente] erro: " + e.getMessage());
        }
    }

    // Caso 3b: monta requisicao e troca o HMAC por um aleatorio
    private void testarHMACCorrompido(String nome) {
        try {
            String edge = descobrirEdge(nome);
            int porta = Integer.parseInt(edge.split(":")[1]);
            PublicKey pubEdge = SegurancaUtils.carregarPublica("edge_" + porta);
            var ctx = SegurancaUtils.criarMensagemSegura("GET /" + nome, pubEdge);

            // split no ":", substitui o tag por um aleatorio de mesmo tamanho
            String[] partes = ctx.pacote.split(":");
            byte[] fakeTag = new byte[32];
            new SecureRandom().nextBytes(fakeTag);
            partes[4] = Base64.getEncoder().encodeToString(fakeTag);
            String pacCorrompido = String.join(":", partes);

            try (java.net.Socket s = new java.net.Socket("127.0.0.1", porta);
                 java.io.PrintWriter out = new java.io.PrintWriter(s.getOutputStream(), true)) {
                out.println(pacCorrompido);
                byte[] r = s.getInputStream().readAllBytes();
                if (r.length == 0) {
                    System.out.println("[Cliente] servidor encerrou conexao (HMAC rejeitado) - CORRETO");
                } else {
                    System.out.println("[Cliente] inesperado: " + r.length + " bytes");
                }
            }
        } catch (Exception e) {
            System.out.println("[Cliente] excecao esperada: " + e.getClass().getSimpleName());
        }
    }


    private void registrar(String linha) {
        synchronized (logs) { logs.add(linha); }
        System.out.println(linha);
    }

    public static void main(String[] args) {
        new ClienteCDN("127.0.0.1", 5354);
    }
}