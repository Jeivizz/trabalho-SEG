package org.example.pratica2;
import org.example.pratica2.impl.ImplServidorDiretorio;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;


import java.security.KeyPair;

import java.util.ArrayList;
import java.util.List;



public class ServidorDiretorio {
    int porta;
    public static KeyPair chavesRSA;
    public static List<String> servidores = new ArrayList<>();
    public static int indiceRoundRobin = 0;

    public ServidorDiretorio(int porta) {
        this.porta = porta;
        try {
            chavesRSA = SegurancaUtils.gerarParChavesRSA();
            SegurancaUtils.salvarChavePublica("dir_pub.key", chavesRSA.getPublic());
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.rodar();
    }

    private void rodar() {
        try {
            ServerSocket socketServidor = new ServerSocket(porta);
            System.out.println("[Diretorio] Rodando seguro na porta " + socketServidor.getLocalPort());
            while (true) {
                Socket cliente = socketServidor.accept();
                new Thread(new ImplServidorDiretorio(cliente)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new ServidorDiretorio(9000);
    }
}

