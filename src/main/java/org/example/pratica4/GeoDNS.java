package org.example.pratica4;

import org.example.pratica4.impl.ImplGeoDNS;
import org.example.pratica4.impl.SegurancaUtils;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.KeyPair;

public class GeoDNS {
    int porta;
    public KeyPair keyPair;

    // Construtor GeoDNS e inicia seu funcionamento ao ser instanciado - rodar();
    public GeoDNS(int porta) throws Exception {
        this.porta = porta;
        this.keyPair = SegurancaUtils.carregarOuCriarKeyPair("geodns");
        this.rodar();
    }

    // GeoDNS rodando pelo UDP, iniciado ao instanciar o objeto
    private void rodar() {
        try (DatagramSocket servidor = new DatagramSocket(porta)) {
            System.out.println("[GeoDNS] UDP escutando na porta " + porta);
            // Vai ficar recebendo os pacotes na porta definida
            while (true) {
                byte[] buf = new byte[4096];
                DatagramPacket pacote = new DatagramPacket(buf, buf.length);
                servidor.receive(pacote);
                new Thread(new ImplGeoDNS(servidor, pacote, keyPair)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        new GeoDNS(5354); // Usei 5354 pois na minha máquina 5353 estava sempre em uso
    }
}