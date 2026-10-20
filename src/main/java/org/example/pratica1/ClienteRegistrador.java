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

// Registrador: faz handshake como REGISTRADOR (com segredo) e envia UPDATE cifrado.
// Não registra para NOTIFY, ele é quem origina a mudança.
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
            // Handshake com papel REGISTRADOR + segredo (autorização no servidor)
            this.sessao = Handshake.estabelecer(s, servidor, Protocolo.PAPEL_REGISTRADOR, NOME, segredo);
        } catch (IOException e) {
            s.close();
            throw e;
        }
        this.socket = s;
    }

    // Envia UPDATE cifrado e espera confirmação cifrada (ATUALIZADO ou ERRO)
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
                continue; // ignora pacotes não cifrados
            }
            try {
                String resp = sessao.abrir(texto); // valida HMAC e decifra
                Log.info(NOME, "RECEBIDO [" + sessao.rotulo() + "] HMAC=OK " + Sessao.resumo(texto)
                        + " | claro=\"" + resp + "\"");
                return resp;
            } catch (FalhaIntegridadeException e) {
                // Resposta com HMAC inválido, descarta e continua esperando
                Log.info(NOME, "FALHA DE INTEGRIDADE: " + e.getMessage() + " -> pacote DESCARTADO");
            }
        }
    }

    public void fechar() {
        socket.close();
    }

    // Permite rodar o registrador como processo independente 
    // Ponto de entrada do registrador quando roda como PROCESSO INDEPENDENTE
    // Uso: java ClienteRegistrador [host] [porta] [segredo]
    public static void main(String[] args) throws Exception {

        // Le os parâmetros da linha de comando, com valores padrão
        // args[0] = host do DNS padrão "localhost"
        String host = args.length > 0 ? args[0] : "localhost";

        // args[1] = porta UDP do DNS padrão 5300, definida em DnsServer
        int porta = args.length > 1 ? Integer.parseInt(args[1]) : DnsServer.PORTA_PADRAO;

        // args[2] = segredo do registrador (padrão "registrador123").
        // Só o registrador conhece esse segredo: ele vai DENTRO do blob cifrado
        // no KEYEX e é validado pelo servidor em tratarKeyex().
        // Se estiver errado, o servidor recusa o handshake.
        String segredo = args.length > 2 ? args[2] : DnsServer.SEGREDO_PADRAO;

        // Estabelece o canal seguro com o DNS (handshake híbrido)
        // O construtor faz: HELLO -> PUBKEY -> KEYEX (RSA-OAEP) -> KEYOK.
        // Se o DNS estiver fora do ar, o segredo estiver errado ou a confirmação
        // falhar, lança IOException.
        ClienteRegistrador r;
        try {
            r = new ClienteRegistrador(host, porta, segredo);
        } catch (IOException e) {
            // Falha no handshake: informa e ENCERRA o programa (return dentro do main).
            // Sem isso, o registrador ficaria inutilizável (sem sessão cifrada).
            System.out.println("Nao foi possível estabelecer o canal seguro com o DNS: " + e.getMessage());
            return;
        }

        // Loop interativo de comandos via teclado
        System.out.println("Comandos: atualizar <nome> <ip> | sair");

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String linha;

        while ((linha = in.readLine()) != null) {
            linha = linha.trim(); // remove espaços nas pontas

            if (linha.equals("sair")) {
                break;
            }

            // Quebra a linha em tokens por espaços
            String[] t = linha.split("\\s+");

            // Valida o formato ANTES de chamar o servidor:
            // precisa ter exatamente 3 tokens e o primeiro ser "atualizar".
            // Se for inválido, NADA é enviado ao DNS (entrada inválida não propaga).
            if (t.length == 3 && t[0].equals("atualizar")) {

               
                String resp = r.atualizar(t[1], t[2]);

                
                if (Protocolo.ehErroDeEntrada(resp)) {
                    Log.info(NOME, Protocolo.MSG_ERRO_ENTRADA
                            + " (servidor: " + resp.substring(4).trim() + ")");
                } else {
                    // Resposta de sucesso (ex.: "ATUALIZADO servidor1 10.0.0.11")
                    Log.info(NOME, "Resultado: " + resp);
                }

            } else if (!linha.isEmpty()) {
                // Comando desconhecido não vazio: imprime a mensagem padronizada
                // com a ajuda de uso. nao chama o servidor
                System.out.println(Protocolo.MSG_ERRO_ENTRADA
                        + " (use: atualizar <nome> <ip> | sair)");
            }
        }


        // Encerra o socket do registrador
        // Como o registrador é um processo que termina
        // fechar o socket libera o recurso do SO.
        r.fechar();
    }
}