package org.example.pratica2.impl;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class ImplServidorDiretorio implements Runnable {
    public Socket socketCliente;
    private static List<String> servidores = new ArrayList<>(); // Lista dos servidores registrados em Servidor Diretório
    private static int indexRoundRobin = 0; // Índice do Round Robin
    private Scanner entrada = null;
    private PrintStream saida = null;

    public ImplServidorDiretorio(Socket cliente) {
        this.socketCliente = cliente;
    }

    @Override
    public void run() {
        try {
            entrada = new Scanner(socketCliente.getInputStream());
            saida = new PrintStream(socketCliente.getOutputStream());

            if (entrada.hasNextLine()) {
                // Lê o comando passado (/REGISTRAR ou DESCOBRIR
                String cmd = entrada.nextLine();

                if (cmd.startsWith("/REGISTRAR")) {
                    String address = cmd.split(" ")[1]; // Separa o endereço do comando
                    synchronized (servidores) { // Synchronized com 'servidores como parêmetro para registrar na ordem certa
                        if (!servidores.contains(address)) { // Verifica se o endereço do comando ainda não existe em servidores
                            servidores.add(address);
                        }
                    }
                    saida.println("OK");
                    System.out.println("[SERVIDOR REGISTRADO]: " + address);

                } else if (cmd.equals("/DESCOBRIR")) {
                    synchronized (servidores) {
                        if (servidores.isEmpty()) {
                            saida.println("[NENHUM SERVIDOR DISPONÍVEL]");
                        } else {
                            String target = servidores.get(indexRoundRobin); // Pega o indice o RoundRobin e define como alvo
                            indexRoundRobin = (indexRoundRobin + 1) % servidores.size(); // Garantir que o index seja circular, dentro do espaço [0 até (size - 1)]
                            saida.println(target); // Retorna o servidor alvo disponível
                        }
                    }
                }
            }

            entrada.close();
            saida.close();
            socketCliente.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
