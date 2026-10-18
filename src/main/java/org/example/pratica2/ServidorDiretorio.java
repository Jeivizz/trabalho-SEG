package org.example.pratica2;
import org.example.pratica2.impl.ImplServidorDiretorio;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ServidorDiretorio {
    int porta;

    public ServidorDiretorio(int porta) {
        this.porta = porta;
        this.rodar(); // Roda Servidor Diretório ao ser instanciado
    }

    private void rodar() {
        try {
            ServerSocket socketServidor = new ServerSocket(porta); // Define o Server Socket do servidor Diretório com sua porta
            System.out.println("Servidor de Diretório rodando na porta [" + socketServidor.getLocalPort() + "]");
            while(true) {
                Socket cliente = socketServidor.accept();
                ImplServidorDiretorio servidor = new ImplServidorDiretorio(cliente);
                // Define e inicia a Thread
                Thread t = new Thread(servidor);
                t.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new ServidorDiretorio(9000);
    }
}
