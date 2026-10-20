package org.example.pratica4;

import org.example.pratica4.impl.ImplEdgeServer;
import org.example.pratica4.impl.SegurancaUtils;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class EdgeServer {
    int porta;
    public static List<String> logs = new ArrayList<>();
    public KeyPair keyPair;

    // Construtor EdgeServer e seu método
    public EdgeServer(int porta) throws Exception {
        this.porta = porta;
        this.keyPair = SegurancaUtils.carregarOuCriarKeyPair("edge_" + porta);
        this.rodar();
    }

    // Roda assim que o objeto EdgeServer é iniciado
    private void rodar() {
        // cache proprio deste Edge
        ConcurrentHashMap<String, ImplEdgeServer.CacheItem> cacheLocal = new ConcurrentHashMap<>();
        // escutando via TCP pela porta definida
        try (ServerSocket servidor = new ServerSocket(porta)) {
            System.out.println("[Edge " + porta + "] TCP escutando");
            while (true) {
                Socket cliente = servidor.accept();
                new Thread(new ImplEdgeServer(cliente, porta, cacheLocal, keyPair)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Função auxiliar para o registro de log
    public static void registrar(String linha) {
        synchronized (logs) { logs.add(linha); }
        System.out.println(linha);
    }

    // Instanciando os 3 servidores de teste
    public static void main(String[] args) {
        new Thread(() -> { try { new EdgeServer(8001); } catch (Exception e) { e.printStackTrace(); } }).start();
        new Thread(() -> { try { new EdgeServer(8002); } catch (Exception e) { e.printStackTrace(); } }).start();
        new Thread(() -> { try { new EdgeServer(8003); } catch (Exception e) { e.printStackTrace(); } }).start();
    }
}