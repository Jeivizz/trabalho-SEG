package org.example.pratica4;

import org.example.pratica4.impl.ImplEdgeServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class EdgeServer {
    int porta;
    public static List<String> logs = new ArrayList<>();

    public EdgeServer(int porta) {
        this.porta = porta;
        this.rodar();
    }

    private void rodar() {
        // PPassa o cache para cada thread
        ConcurrentHashMap<String, ImplEdgeServer.CacheItem> cacheLocal = new ConcurrentHashMap<>();

        try (ServerSocket servidor = new ServerSocket(porta)) {
            System.out.println("Edge Server (TCP) na porta [" + porta + "]");
            while (true) {
                Socket cliente = servidor.accept();
                // uma thread por conexão pra nao travar no accept
                new Thread(new ImplEdgeServer(cliente, porta, cacheLocal)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void registrar(String linha) {
        synchronized (logs) {
            logs.add(linha);
        }
        System.out.println(linha);
    }

    public static void main(String[] args) {
        // sobe os 3 Edges em threads separadas. cada um com cache proprio
        new Thread(() -> new EdgeServer(8001)).start();
        new Thread(() -> new EdgeServer(8002)).start();
        new Thread(() -> new EdgeServer(8003)).start();
    }
}