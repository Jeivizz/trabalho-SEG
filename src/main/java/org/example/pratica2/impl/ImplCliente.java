package org.example.pratica2.impl;

import org.example.pratica2.ServidorCalculadora;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.Scanner;

public class ImplCliente implements Runnable {
    String idCliente, operacao, entradaBruta;

    public ImplCliente(String idCliente, String operacao, String entradaBruta) {
        this.idCliente = idCliente;
        this.operacao = operacao;
        this.entradaBruta = entradaBruta; // Entrada passada pelo cliente
    }

    @Override
    public void run() {
        String address = descobrirServidor(); // Descobre o servidor disponível pelo RoundRobin
        if (address == null || address.equals("[NENHUM SERVIDOR DISPONÍVEL]")) {
            System.out.println(idCliente + " - [NENHUM SERVIDOR DISPONÍVEL]");
            return;
        }

        String[] partes = address.split(":"); // Separa o endereço e a porta XXX.XXX.XXX.XXX:YYYYY
        try {
            Socket socket = new Socket(partes[0], Integer.parseInt(partes[1]));
            PrintStream saida = new PrintStream(socket.getOutputStream());
            Scanner entrada = new Scanner(socket.getInputStream());

            String comandoCompleto = operacao + " " + entradaBruta; // Faz um assemble do comando para ser exibido. EX: SOMA 10 5"
            saida.println(comandoCompleto);

            if (entrada.hasNextLine()) {
                String resp = entrada.nextLine();
                synchronized (System.out) { // Synchronized apenas pela formatação, para as linhas divisoras
                    System.out.println(idCliente + " solicitou [" + comandoCompleto + "] a [" + address + "]");
                    System.out.println(resp);
                    System.out.println("-----------------------------------------------------------------------------------------------------");

                    /* EXEMPLO:
                        Cliente 3 solicitou [DIVISAO 20 4] a [127.0.0.1:9003]
                        [CalcServer-3] Resultado: 5.0
                        -----------------------------------------------------------------------------------------------------
                    */
                }

            }
            entrada.close();
            saida.close();
            socket.close();
        } catch (IOException e) {
            synchronized (System.out) {
                System.out.println("[ERRO]: " + e.getMessage());
            }

        }
    }

    // Função para descobrir o Servidor Disponível
    private String descobrirServidor() {
        try {
            Socket socket = new Socket("127.0.0.1", 9000); // Servidor Diretório
            PrintStream saida = new PrintStream(socket.getOutputStream());
            Scanner entrada = new Scanner(socket.getInputStream());

            saida.println("/DESCOBRIR"); // Envia /DESCOBRIR para o Servidor Diretório
            String resposta = entrada.hasNextLine() ? entrada.nextLine() : null; // Resposta com o servidor calculado pelo RoundRobin

            entrada.close();
            saida.close();
            socket.close();
            return resposta;
        } catch (IOException e) {
            return null;
        }
    }
}