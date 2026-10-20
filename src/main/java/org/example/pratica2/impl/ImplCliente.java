package org.example.pratica2.impl;

import java.io.PrintStream;
import java.net.ConnectException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;

public class ImplCliente implements Runnable {
    String idCliente, operacao, entradaBruta;
    boolean forcarFalhaHmac;
    KeyPair chavesCliente;

    public ImplCliente(String idCliente, String operacao, String entradaBruta, boolean forcarFalhaHmac) {
        this.idCliente = idCliente;
        this.operacao = operacao;
        this.entradaBruta = entradaBruta;
        this.forcarFalhaHmac = forcarFalhaHmac;
        try {
            this.chavesCliente = SegurancaUtils.gerarParChavesRSA();
        } catch (Exception e) { e.printStackTrace(); }
    }

    @Override
    public void run() {
        String enderecoCompleto = descobrirSeguro();
        if (enderecoCompleto == null || enderecoCompleto.equals("NENHUM_SERVIDOR_DISPONIVEL")) {
            System.out.println("[" + idCliente + "] Nenhum servidor disponível.");
            return;
        }

        String[] dadosServidor = enderecoCompleto.split("\\|");
        String endereco = dadosServidor[0]; // "127.0.0.1:9001"

        try {
            PublicKey calcPubKey = SegurancaUtils.stringToPublicKey(dadosServidor[1]); // A chave pública da calculadora
            String[] partes = endereco.split(":");

            try (Socket socket = new Socket(partes[0], Integer.parseInt(partes[1]));
                 PrintStream saida = new PrintStream(socket.getOutputStream());
                 Scanner entrada = new Scanner(socket.getInputStream())) {

                String payload = operacao + " " + entradaBruta + "|" + SegurancaUtils.publicKeyToString(chavesCliente.getPublic());
                String pacoteCifrado = SegurancaUtils.criarMensagemSegura(payload, calcPubKey);

                if (forcarFalhaHmac) {
                    pacoteCifrado = pacoteCifrado.substring(0, pacoteCifrado.length() - 5) + "ABCDE";
                }

                saida.println(pacoteCifrado);

                if (entrada.hasNextLine()) {
                    String respostaCifrada = entrada.nextLine();
                    String respostaDecifrada = SegurancaUtils.decriptarEValidarMensagem(respostaCifrada, chavesCliente.getPrivate());

                    synchronized (System.out) {
                        System.out.println("[" + idCliente + "] Operação [" + operacao + " " + entradaBruta + "] enviada com segurança para [" + endereco + "]");
                        System.out.println("[" + idCliente + "] Resposta decifrada: " + respostaDecifrada);
                        System.out.println("--------------------------------------------------");
                    }
                } else {
                    synchronized (System.out) {
                        System.out.println("[" + idCliente + "] [ERRO]: Pacote descartado pelo servidor (HMAC inválido/Corrompido).");
                        System.out.println("--------------------------------------------------");
                    }
                }
            }
        } catch (ConnectException e) {
            synchronized (System.out) {
                System.out.println("[" + idCliente + "] [ERRO]: Servidor inativo/indisponível em " + endereco);
                System.out.println("--------------------------------------------------");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String descobrirSeguro() {
        try (Socket socket = new Socket("127.0.0.1", 9000);
             PrintStream saida = new PrintStream(socket.getOutputStream());
             Scanner entrada = new Scanner(socket.getInputStream())) {

            PublicKey dirPubKey = SegurancaUtils.carregarChavePublica("dir_pub.key");

            String payload = "/DESCOBRIR|" + SegurancaUtils.publicKeyToString(chavesCliente.getPublic());
            String pacoteCifrado = SegurancaUtils.criarMensagemSegura(payload, dirPubKey);
            saida.println(pacoteCifrado);

            if (entrada.hasNextLine()) {
                String respostaCifrada = entrada.nextLine();
                String respostaDecifrada = SegurancaUtils.decriptarEValidarMensagem(respostaCifrada, chavesCliente.getPrivate());

                synchronized (System.out) {
                    System.out.println("[" + idCliente + "] Consulta cifrada ao Diretório obteve endereço autenticado: [" + respostaDecifrada.split("\\|")[0] + "]");
                }

                return respostaDecifrada;
            }

            return null;
        } catch (Exception e) {
            return null;
        }
    }
}