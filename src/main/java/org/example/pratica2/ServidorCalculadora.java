package org.example.pratica2;

import org.example.pratica2.impl.ImplServidorCalculadora;

import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;

public class ServidorCalculadora {
    static final String IP_DIRETORIO = "127.0.0.1";
    static final int PORTA_DIRETORIO = 9000;

    int porta;
    String nome;

    public ServidorCalculadora(String nome, int porta) {
        this.nome = nome;
        this.porta = porta;
        this.registrarDiretorio();
        this.rodar(); /// Coloca o Servidor Calculadora para rodar assim que o objeto é instanciado
    }

    // Função para registrar o endereço e porta do Servidor Diretório
    private void registrarDiretorio() {
        try {
            Socket socket = new Socket(IP_DIRETORIO, PORTA_DIRETORIO); // Instancia o Socket do Servidor Diretório
            PrintStream saida = new PrintStream(socket.getOutputStream());
            saida.println("/REGISTRAR " + IP_DIRETORIO + ":" + this.porta); // Retorno do Servidor Calculadora registrado no Diretório
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Função para iniciar o Servidor Diretório automaticamente ao ser instanciado
    private void rodar() {
        try {
            ServerSocket socketServidor = new ServerSocket(porta); // Definição do ServerSocket do Servidor Calculadora
            System.out.println(nome + " rodando na porta [" + socketServidor.getLocalPort() + "]");
            while (true) {
                Socket cliente = socketServidor.accept();
                ImplServidorCalculadora servidor = new ImplServidorCalculadora(cliente, nome);
                // Instancia e inicia a Thread
                Thread t = new Thread(servidor);
                t.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Thread(() -> new ServidorCalculadora("CalcServer-1", 9001)).start();
        new Thread(() -> new ServidorCalculadora("CalcServer-2", 9002)).start();
        new Thread(() -> new ServidorCalculadora("CalcServer-3", 9003)).start();
    }
}
