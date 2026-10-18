package org.example.pratica2.impl;

import org.example.pratica2.SegurancaUtils;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;

public class ImplServidorCalculadora implements Runnable {
    private Socket socketCliente;
    private String nomeServidor;
    private KeyPair chavesRSA;

    public ImplServidorCalculadora(Socket cliente, String nomeServidor, KeyPair chaves) {
        this.socketCliente = cliente;
        this.nomeServidor = nomeServidor;
        this.chavesRSA = chaves;
    }

    @Override
    public void run() {
        try (Scanner entrada = new Scanner(socketCliente.getInputStream());
             PrintStream saida = new PrintStream(socketCliente.getOutputStream())) {

            if (entrada.hasNextLine()) {
                String pacoteSeguro = entrada.nextLine();
                try {
                    String payload = SegurancaUtils.decriptarEValidarMensagem(pacoteSeguro, chavesRSA.getPrivate());

                    // Formato: "SOMA 10 20 | CHAVE_PUB_CLIENTE"
                    String[] partesPayload = payload.split("\\|");
                    String dadosCalculo = partesPayload[0].trim();
                    PublicKey clientePubKey = SegurancaUtils.stringToPublicKey(partesPayload[1].trim());

                    String[] partes = dadosCalculo.split(" ");
                    String operacao = partes[0];

                    if (!operacao.equals("SOMA") && !operacao.equals("SUBTRACAO") &&
                            !operacao.equals("MULTIPLICACAO") && !operacao.equals("DIVISAO")) {
                        throw new IllegalArgumentException("Erro na entrada de dados. Tente outra vez!");
                    }

                    double a = Double.parseDouble(partes[1]);
                    double b = Double.parseDouble(partes[2]);
                    double result = 0;

                    switch (operacao) {
                        case "SOMA": result = a + b; break;
                        case "SUBTRACAO": result = a - b; break;
                        case "MULTIPLICACAO": result = a * b; break;
                        case "DIVISAO":
                            if (b == 0) throw new IllegalArgumentException("Erro na entrada de dados. Tente outra vez!");
                            result = a / b; break;
                    }

                    // Envia resposta cifrada para o cliente
                    String msgResposta = "[" + nomeServidor + "] Processado com segurança. Resultado: " + result;
                    saida.println(SegurancaUtils.criarMensagemSegura(msgResposta, clientePubKey));

                } catch (SecurityException e) {
                    System.out.println("[" + nomeServidor + "] Falha de integridade barrada: " + e.getMessage());
                    // Em caso de falha de HMAC, o servidor não responde ou encerra a conexão.
                } catch (Exception e) {
                    // Para erros de entrada (ex: NumberFormatException, ArrayIndexOutOfBounds), tenta avisar o cliente
                    try {
                        String[] partesPayload = SegurancaUtils.decriptarEValidarMensagem(pacoteSeguro, chavesRSA.getPrivate()).split("\\|");
                        if(partesPayload.length > 1) {
                            PublicKey clientePubKey = SegurancaUtils.stringToPublicKey(partesPayload[1].trim());
                            String erroMsg = "Erro na entrada de dados. Tente outra vez!";
                            saida.println(SegurancaUtils.criarMensagemSegura(erroMsg, clientePubKey));
                        }
                    } catch (Exception ex) {
                        // Se nem a chave do cliente puder ser lida, ignora
                    }
                }
            }
        } catch (Exception e) {
            // Erro de IO ao fechar conexao
        }
    }
}