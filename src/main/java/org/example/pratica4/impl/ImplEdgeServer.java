package org.example.pratica4.impl;

import org.example.pratica4.EdgeServer;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ImplEdgeServer implements Runnable {
    public Socket socketCliente;
    public int portaEdge;
    private final ConcurrentHashMap<String, CacheItem> cache;
    private final KeyPair keyPairEdge;

    // Quantidade de arquivos por cache
    private static final int LIMITE_CACHE = 100;
    // TTL de espera
    private static final long TTL_MILLIS = 10_000;

    // Classe CacheItem, para o cache individual de cada Edge
    public static class CacheItem {
        final String conteudo;
        final int length;
        final long inseridoEm;
        CacheItem(String c) { conteudo = c; length = c.length(); inseridoEm = System.currentTimeMillis(); }
        boolean expirado() { return System.currentTimeMillis() - inseridoEm > TTL_MILLIS; }
    }

    // Construtor de ImplEdgeServer
    public ImplEdgeServer(Socket cliente, int porta,
                          ConcurrentHashMap<String, CacheItem> cache, KeyPair kp) {
        this.socketCliente = cliente;
        this.portaEdge = porta;
        this.cache = cache;
        this.keyPairEdge = kp;
    }

    @Override
    public void run() {
        try (Socket s = socketCliente;
             BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
             PrintWriter out = new PrintWriter(s.getOutputStream(), true)) {

            String pacote = in.readLine();
            if (pacote == null || pacote.isEmpty()) return;

            SegurancaUtils.MensagemDecifrada msg;
            try {
                msg = SegurancaUtils.decriptarEValidarMensagem(pacote, keyPairEdge.getPrivate());
            } catch (Exception e) {
                // Caso 3b/3c: HMAC errado, RSA invalido ou pacote mal formado -> fecha socket, não mexe no cache
                EdgeServer.registrar("[Edge " + portaEdge + "] falha de integridade - encerrando conexao");
                s.close();
                return;
            }

            // Integridade Ok, Decifragem Ok
            EdgeServer.registrar("[Edge " + portaEdge + "] HMAC validado + payload decifrado: " + msg.payload);

            // INVALIDATE vindo do Origin
            if (msg.payload.startsWith("INVALIDATE ")) {
                String nome = msg.payload.substring("INVALIDATE ".length()).trim();
                if (nome.startsWith("/")) nome = nome.substring(1);
                cache.remove(nome);
                EdgeServer.registrar("[Edge " + portaEdge + "] cache invalidado: " + nome);
                return;
            }

            if (!msg.payload.startsWith("GET ")) {
                responder(out, msg, "400 Bad Request");
                return;
            }

            String nome = msg.payload.substring(4).trim();
            if (nome.startsWith("/")) nome = nome.substring(1);

            // Caso 3a: formato invalido
            if (!nome.matches("arquivo\\d+\\.ext")) {
                EdgeServer.registrar("[Edge " + portaEdge + "] formato invalido: " + nome);
                responder(out, msg, "Erro na entrada de dados. Tente outra vez!");
                return;
            }

            CacheItem item = cache.get(nome);

            // HIT
            if (item != null && !item.expirado()) {
                EdgeServer.registrar("[Edge " + portaEdge + "] HIT " + nome);
                responder(out, msg, "200 OK\nCache: HIT\nLength: " + item.length + "\n" + item.conteudo);
                return;
            }

            // TTL expirado
            if (item != null) {
                EdgeServer.registrar("[Edge " + portaEdge + "] TTL expirado " + nome);
                cache.remove(nome);
            }

            // MISS
            EdgeServer.registrar("[Edge " + portaEdge + "] MISS " + nome);
            String conteudo = buscarNaOrigem(nome);
            if (conteudo == null) {
                responder(out, msg, "404 Not Found");
                return;
            }

            guardarNoCache(nome, conteudo);
            responder(out, msg, "200 OK\nCache: MISS\nLength: " + conteudo.length() + "\n" + conteudo);

        } catch (Exception e) {
            System.out.println("[Edge " + portaEdge + "] erro: " + e.getMessage());
        }
    }

    private void responder(PrintWriter out, SegurancaUtils.MensagemDecifrada msg, String payload)
            throws Exception {
        out.println(SegurancaUtils.criarRespostaSegura(payload, msg.aesKey, msg.hmacKey));
        EdgeServer.registrar("[Edge " + portaEdge + "] resposta cifrada enviada");
    }

    // FIFO, Arquivos mais antigos são apagados para dar espaço aos novos
    private void guardarNoCache(String nome, String conteudo) {
        if (cache.size() >= LIMITE_CACHE) {
            Iterator<Map.Entry<String, CacheItem>> it = cache.entrySet().iterator();
            Map.Entry<String, CacheItem> maisAntigo = null;
            while (it.hasNext()) {
                var e = it.next();
                if (maisAntigo == null || e.getValue().inseridoEm < maisAntigo.getValue().inseridoEm)
                    maisAntigo = e;
            }
            if (maisAntigo != null) {
                cache.remove(maisAntigo.getKey());
                EdgeServer.registrar("[Edge " + portaEdge + "] apaga: " + maisAntigo.getKey());
            }
        }
        cache.put(nome, new CacheItem(conteudo));
    }

    // conexão cifrada com o Origin
    private String buscarNaOrigem(String nome) throws Exception {
        try (Socket s = new Socket("127.0.0.1", 8000);
             PrintWriter out = new PrintWriter(s.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()))) {

            PublicKey pubOrigin = SegurancaUtils.carregarPublica("origin");
            var ctx = SegurancaUtils.criarMensagemSegura("GET /" + nome, pubOrigin);

            out.println(ctx.pacote);
            String resp = in.readLine();
            if (resp == null) return null;

            String texto = SegurancaUtils.decifrarResposta(resp, ctx.aesKey, ctx.hmacKey);
            if (!texto.startsWith("200 OK")) return null;
            String[] linhas = texto.split("\n", 3); // "200 OK\nLength: N\nCONTEUDO"
            return linhas.length >= 3 ? linhas[2] : null;
        }
    }
}