package org.example.pratica4.impl;

import org.example.pratica4.EdgeServer;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;

public class ImplEdgeServer implements Runnable {
    public Socket socketCliente;
    public int portaEdge;

    // Cache desse Edge
    private final ConcurrentHashMap<String, CacheItem> cache;

    private static final int LIMITE_CACHE = 100;
    private static final long TTL_MILLIS = 10_000;

    // Guarda o conteudo pra checar o TTL
    public static class CacheItem {
        final String conteudo;
        final int length;
        final long inseridoEm;

        CacheItem(String c) {
            this.conteudo = c;
            this.length = c.length();
            this.inseridoEm = System.currentTimeMillis();
        }

        boolean expirado() {
            return System.currentTimeMillis() - inseridoEm > TTL_MILLIS;
        }
    }

    public ImplEdgeServer(Socket cliente, int porta, ConcurrentHashMap<String, CacheItem> cache) {
        this.socketCliente = cliente;
        this.portaEdge = porta;
        this.cache = cache;
    }

    @Override
    public void run() {
        try (Scanner entrada = new Scanner(socketCliente.getInputStream());
             PrintStream saida = new PrintStream(socketCliente.getOutputStream())) {

            if (!entrada.hasNextLine()) return;
            String linha = entrada.nextLine();
            EdgeServer.registrar("[Edge " + portaEdge + "] recebido: " + linha);

            // Invalidação: tira do cache e encerra
            if (linha.startsWith("INVALIDATE ")) {
                String arquivo = linha.substring("INVALIDATE ".length()).trim();
                if (arquivo.startsWith("/")) arquivo = arquivo.substring(1);
                cache.remove(arquivo);
                EdgeServer.registrar("[Edge " + portaEdge + "] cache invalidado: " + arquivo);
                return;
            }

            if (!linha.startsWith("GET ")) {
                saida.println("400 Bad Request");
                return;
            }

            String arquivo = linha.substring(4).trim();
            if (arquivo.startsWith("/")) arquivo = arquivo.substring(1);

            CacheItem item = cache.get(arquivo);

            //HIT
            if (item != null && !item.expirado()) {
                EdgeServer.registrar("[Edge " + portaEdge + "] HIT " + arquivo);
                saida.println("200 OK");
                saida.println("Cache: HIT");
                saida.println("Length: " + item.length);
                saida.println(item.conteudo);
                return;
            }

            // Descarta antes de ir na origem, caso o TTL estoure
            if (item != null) {
                EdgeServer.registrar("[Edge " + portaEdge + "] TTL estourou pra " + arquivo);
                cache.remove(arquivo);
            }

            // Vai na origem buscar em caso de MISS
            EdgeServer.registrar("[Edge " + portaEdge + "] MISS " + arquivo);
            String conteudo = buscarNaOrigem(arquivo);

            if (conteudo == null) {
                saida.println("404 Not Found");
                return;
            }

            guardarNoCache(arquivo, conteudo);

            saida.println("200 OK");
            saida.println("Cache: MISS");
            saida.println("Length: " + conteudo.length());
            saida.println(conteudo);

        } catch (IOException e) {
            System.out.println("[Edge " + portaEdge + "] erro na conexao: " + e.getMessage());
        }
    }

    // Se o cache ficar cheio, tira o item mais antigo pra abrir espaco. (FIFO)
    private void guardarNoCache(String arquivo, String conteudo) {
        if (cache.size() >= LIMITE_CACHE) {
            Iterator<Map.Entry<String, CacheItem>> it = cache.entrySet().iterator();
            Map.Entry<String, CacheItem> maisAntigo = null;
            while (it.hasNext()) {
                Map.Entry<String, CacheItem> atual = it.next();
                if (maisAntigo == null || atual.getValue().inseridoEm < maisAntigo.getValue().inseridoEm) {
                    maisAntigo = atual;
                }
            }
            if (maisAntigo != null) {
                cache.remove(maisAntigo.getKey());
                EdgeServer.registrar("[Edge " + portaEdge + "] eviccao FIFO: " + maisAntigo.getKey());
            }
        }
        cache.put(arquivo, new CacheItem(conteudo));
    }

    private String buscarNaOrigem(String arquivo) {
        // conexão curta com o origin so pra pegar o arquivo
        try (Socket s = new Socket("127.0.0.1", 8000);
             PrintStream out = new PrintStream(s.getOutputStream());
             Scanner in = new Scanner(s.getInputStream())) {

            out.println("GET /" + arquivo);

            String status = in.hasNextLine() ? in.nextLine() : "";
            if (!"200 OK".equals(status)) return null;

            if (in.hasNextLine()) in.nextLine(); // "Length: X" - vou recalcular pelo conteudo mesmo
            return in.hasNextLine() ? in.nextLine() : null;

        } catch (IOException e) {
            System.out.println("[Edge " + portaEdge + "] nao consegui falar com o Origin");
            return null;
        }
    }
}