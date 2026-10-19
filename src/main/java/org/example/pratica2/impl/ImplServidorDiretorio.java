package org.example.pratica2.impl;

import org.example.pratica2.ServidorDiretorio;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Scanner;

public class ImplServidorDiretorio implements Runnable {
    private Socket socketCliente;

    public ImplServidorDiretorio(Socket cliente) {
        this.socketCliente = cliente;
    }

    @Override
    public void run() {
        // try-with-resources garante que os streams e o socket serão fechados automaticamente,
        try (Scanner entrada = new Scanner(socketCliente.getInputStream());
             PrintStream saida = new PrintStream(socketCliente.getOutputStream())) {

            if (entrada.hasNextLine()) {
                String pacoteSeguro = entrada.nextLine();
                try {
                    // Validação do HMAC. Se o pacote foi adulterado no caminho,
                    String payload = SegurancaUtils.decriptarEValidarMensagem(pacoteSeguro, ServidorDiretorio.chavesRSA.getPrivate());

                    // Divide o payload que chega no formato "/COMANDO | CHAVE_PUBLICA_CLIENTE".
                    String[] partesPayload = payload.split("\\|");
                    String comando = partesPayload[0].trim();

                    // Transforma a parte do payload que possui a chave pública do cliente em PublicKey
                    PublicKey clientePubKey = SegurancaUtils.stringToPublicKey(partesPayload[1].trim());

                    if (comando.startsWith("/REGISTRAR")) {
                        String endereco = comando.split(" ")[1];

                        // Armazena o endereço e a chave pública da calculadora
                        String registroCompleto = endereco + "|" + partesPayload[1].trim();

                        // Synchronized para evitar conflitos de concorrência
                        synchronized (ServidorDiretorio.servidores) {
                            // Evita duplicidade caso o servidor caia e reinicie
                            boolean jaExiste = ServidorDiretorio.servidores.stream()
                                    .anyMatch(s -> s.startsWith(endereco + "|"));
                            if (!jaExiste) {
                                ServidorDiretorio.servidores.add(registroCompleto);
                            }
                        }
                        System.out.println("[Diretorio] Serviço autenticado e registrado: [" + endereco + "]");

                    } else if (comando.equals("/DESCOBRIR")) {
                        String resposta;
                        synchronized (ServidorDiretorio.servidores) {
                            if (ServidorDiretorio.servidores.isEmpty()) {
                                resposta = "NENHUM_SERVIDOR_DISPONIVEL";
                            } else {
                                // RoundRobin para escolher o servidor disponÍvel
                                resposta = ServidorDiretorio.servidores.get(ServidorDiretorio.indiceRoundRobin);
                                ServidorDiretorio.indiceRoundRobin = (ServidorDiretorio.indiceRoundRobin + 1) % ServidorDiretorio.servidores.size();
                            }
                        }

                        // Resposta cifrada
                        String respostaCifrada = SegurancaUtils.criarMensagemSegura(resposta, clientePubKey);
                        saida.println(respostaCifrada);
                        System.out.println("[Diretorio] Resposta enviada de forma cifrada ao cliente.");
                    }
                } catch (SecurityException e) {
                    // Descarta em caso de problema com o HMAC
                    System.out.println("[Diretorio] ALERTA: Pacote descartado. " + e.getMessage());
                } catch (Exception e) {
                    // Captura erros de formatação
                    System.out.println("[Diretorio] Erro de decifragem: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}