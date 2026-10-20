package org.example.pratica1;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

// QUESTÃO 1 (Segurança) - Cliente registrador.
//
// Faz o handshake como REGISTRADOR e prova que tem permissão enviando o segredo
// DENTRO do bloco cifrado com RSA (nunca em claro). Depois envia
// "UPDATE <nome> <ip>" cifrado + HMAC e espera a confirmação com timeout.
public class ClienteRegistrador {

    private static final String NOME = "Registrador";
    private static final int TIMEOUT_MS = 2000;

    private final DatagramSocket socket;
    private final InetSocketAddress servidor;
    private final Sessao sessao;

    public ClienteRegistrador(String host, int portaServidor, String segredo) throws IOException {
        DatagramSocket s = new DatagramSocket();
        s.setSoTimeout(TIMEOUT_MS);
        this.servidor = new InetSocketAddress(InetAddress.getByName(host), portaServidor);
        try {
            this.sessao = Handshake.estabelecer(s, servidor, Protocolo.PAPEL_REGISTRADOR, NOME, segredo);
        } catch (IOException e) {
            s.close();
            throw e;
        }
        this.socket = s;
    }

    public String atualizar(String nome, String ip) throws IOException {
        String claro = "UPDATE " + nome + " " + ip;
        String pacote = sessao.empacotar(claro);
        Log.info(NOME, "ENVIANDO [" + sessao.rotulo() + "] " + Sessao.resumo(pacote) + " | claro=\"" + claro + "\"");
        byte[] dados = pacote.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, servidor));

        while (true) {
            DatagramPacket resposta = new DatagramPacket(new byte[CriptoUtil.TAM_DATAGRAMA], CriptoUtil.TAM_DATAGRAMA);
            try {
                socket.receive(resposta);
            } catch (SocketTimeoutException e) {
                return "ERRO TIMEOUT (sem resposta valida do servidor em " + TIMEOUT_MS + " ms)";
            }
            String texto = new String(resposta.getData(), 0, resposta.getLength(), StandardCharsets.UTF_8).trim();
            if (!texto.startsWith("DATA|")) {
                continue;
            }
            try {
                String resp = sessao.abrir(texto);
                Log.info(NOME, "RECEBIDO [" + sessao.rotulo() + "] HMAC=OK " + Sessao.resumo(texto)
                        + " | claro=\"" + resp + "\"");
                return resp;
            } catch (FalhaIntegridadeException e) {
                Log.info(NOME, "FALHA DE INTEGRIDADE: " + e.getMessage() + " -> pacote DESCARTADO");
            }
        }
    }

    public void fechar() {
        socket.close();
    }

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "localhost";
        int porta = args.length > 1 ? Integer.parseInt(args[1]) : DnsServer.PORTA_PADRAO;
        String segredo = args.length > 2 ? args[2] : DnsServer.SEGREDO_PADRAO;

        ClienteRegistrador r;
        try {
            r = new ClienteRegistrador(host, porta, segredo);
        } catch (IOException e) {
            System.out.println("Nao foi possível estabelecer o canal seguro com o DNS: " + e.getMessage());
            return;
        }

        System.out.println("Comandos: atualizar <nome> <ip> | sair");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String linha;
        while ((linha = in.readLine()) != null) {
            linha = linha.trim();
            if (linha.equals("sair")) {
                break;
            }
            String[] t = linha.split("\\s+");
            if (t.length == 3 && t[0].equals("atualizar")) {
                String resp = r.atualizar(t[1], t[2]);
                if (Protocolo.ehErroDeEntrada(resp)) {
                    Log.info(NOME, Protocolo.MSG_ERRO_ENTRADA + " (servidor: " + resp.substring(4).trim() + ")");
                } else {
                    Log.info(NOME, "Resultado: " + resp);
                }
            } else if (!linha.isEmpty()) {
                System.out.println(Protocolo.MSG_ERRO_ENTRADA + " (use: atualizar <nome> <ip> | sair)");
            }
        }
        r.fechar();
    }
}