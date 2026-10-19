package org.example.pratica2;

import org.example.pratica2.impl.ImplServidorCalculadora;
import org.example.pratica2.impl.SegurancaUtils;

import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;

import java.security.KeyPair;
import java.security.PublicKey;


public class ServidorCalculadora {
    int porta;
    String nome;
    public KeyPair chavesRSA;

    public ServidorCalculadora(String nome, int porta) {
        this.nome = nome;
        this.porta = porta;
        try {
            this.chavesRSA = SegurancaUtils.gerarParChavesRSA();
        } catch (Exception e) { e.printStackTrace(); }

        this.registrarDiretorioSeguro();
        this.rodar();
    }

    private void registrarDiretorioSeguro() {
        try (Socket socket = new Socket("127.0.0.1", 9000);
             PrintStream saida = new PrintStream(socket.getOutputStream())) {

            // Lê a chave pública do Diretório do arquivo
            PublicKey dirPub = SegurancaUtils.carregarChavePublica("dir_pub.key");

            // Registra enviando a chave pública da calculadora junto
            String payload = "/REGISTRAR 127.0.0.1:" + this.porta + "|" + SegurancaUtils.publicKeyToString(this.chavesRSA.getPublic());
            String pacoteCifrado = SegurancaUtils.criarMensagemSegura(payload, dirPub);
            saida.println(pacoteCifrado);

        } catch (Exception e) {
            System.out.println("Erro ao registrar no diretorio. O Diretorio ja iniciou?");
        }
    }

    private void rodar() {
        try {
            ServerSocket socketServidor = new ServerSocket(porta);
            System.out.println("[" + nome + "] Rodando seguro na porta [" + socketServidor.getLocalPort() + "]");
            while (true) {
                Socket cliente = socketServidor.accept();
                new Thread(new ImplServidorCalculadora(cliente, nome, chavesRSA)).start();
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    public static void main(String[] args) {
        new Thread(() -> new ServidorCalculadora("S1", 9001)).start();
        new Thread(() -> new ServidorCalculadora("S2", 9002)).start();
        new Thread(() -> new ServidorCalculadora("S3", 9003)).start();
    }
}

