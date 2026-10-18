package org.example.pratica4;

import org.example.pratica4.impl.ImplGeoDNS;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class GeoDNS {
    int porta;

    public GeoDNS(int porta) {
        this.porta = porta;
        this.rodar();
    }

    private void rodar() {
        try (DatagramSocket servidor = new DatagramSocket(porta)) {
            System.out.println("GeoDNS (UDP) na porta [" + porta + "]");
            while (true) {
                byte[] buffer = new byte[1024];
                DatagramPacket pacote = new DatagramPacket(buffer, buffer.length);
                servidor.receive(pacote);
                new Thread(new ImplGeoDNS(servidor, pacote)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new GeoDNS(5354);
    }
}