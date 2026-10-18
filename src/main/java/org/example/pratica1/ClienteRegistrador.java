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

// QUESTÃO 1 - Cliente registrador.
//
// Simula um serviço que mudou de IP e "se registra de novo" (binding dinâmico).
// Envia UPDATE <nome> <ip> e espera a confirmação com timeout, pois UDP não
// garante entrega: se o datagrama ou a resposta se perder, o cliente não
// fica bloqueado para sempre.
//
// Diferença em relação ao ClienteRequisitante:
//   - NÃO mantém thread ouvinte nem cache: ele é a FONTE da mudança.
//   - NÃO se registra para receber NOTIFY: ele é quem provoca os NOTIFY.
//   - Usa setSoTimeout porque a única coisa que ele faz é enviar UPDATE e
//     esperar uma confirmação pontual (ATUALIZADO ou ERRO).
public class ClienteRegistrador {

    // Tempo máximo que esperamos pela confirmação do servidor. Como UDP não
    // garante entrega, sem esse timeout o cliente ficaria bloqueado para
    // sempre caso a resposta se perdesse.
    private static final int TIMEOUT_MS = 2000;

    private final DatagramSocket socket;
    private final InetSocketAddress servidor;

    public ClienteRegistrador(String host, int portaServidor) throws IOException {
        this.socket = new DatagramSocket();
        // Timeout na recepção: se a confirmação não chegar em TIMEOUT_MS,
        // receive() lança SocketTimeoutException e devolvemos erro ao chamador.
        this.socket.setSoTimeout(TIMEOUT_MS);
        this.servidor = new InetSocketAddress(InetAddress.getByName(host), portaServidor);
    }

    //Envia UPDATE <nome> <ip> e aguarda a confirmação do servidor.
    //
    //     Retorna:
    //   - "ATUALIZADO <nome> <ip>" se o servidor aceitou a mudança;
    //   - "ERRO <motivo>" se o servidor rejeitou (ex.: IP inválido, nome
    //     inexistente);
    //   - "ERRO TIMEOUT ..." se nenhuma resposta chegou dentro de TIMEOUT_MS.
    //
    // O chamador decide o que fazer com o resultado; esta classe não
    // imprime diretamente para não misturar I/O com lógica.
    public String atualizar(String nome, String ip) throws IOException {
        byte[] dados = ("UPDATE " + nome + " " + ip).getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, servidor));

        DatagramPacket resposta = new DatagramPacket(new byte[1024], 1024);
        try {
            socket.receive(resposta);
        } catch (SocketTimeoutException e) {
            return "ERRO TIMEOUT (sem resposta do servidor em " + TIMEOUT_MS + " ms)";
        }
        return new String(resposta.getData(), 0, resposta.getLength(), StandardCharsets.UTF_8).trim();
    }

    public void fechar() {
        socket.close();
    }

    // Modo interativo: java ClienteRegistrador [host] [porta] 
    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "localhost";
        int porta = args.length > 1 ? Integer.parseInt(args[1]) : DnsServer.PORTA_PADRAO;

        ClienteRegistrador r = new ClienteRegistrador(host, porta);
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
                System.out.println("  [Registrador] " + r.atualizar(t[1], t[2]));
            } else if (!linha.isEmpty()) {
                System.out.println("Comando inválido. Use: atualizar <nome> <ip> | sair");
            }
        }
        r.fechar();
    }
}
