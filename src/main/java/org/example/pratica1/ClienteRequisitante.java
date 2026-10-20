package org.example.pratica1;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

// Cliente requisitante: estabelece sessão cifrada com o DNS via handshake,
// registra-se para receber NOTIFY e mantém cache local dos nomes resolvidos.
public class ClienteRequisitante {

    private final String nome;
    private final DatagramSocket socket;
    private final InetSocketAddress servidor;
    private final Sessao sessao; // chaves AES/HMAC negociadas no handshake
    private final Map<String, String> cache = new ConcurrentHashMap<>();
    private volatile boolean ativo = true;

    public ClienteRequisitante(String nome, String host, int portaServidor) throws IOException {
        this.nome = nome;
        DatagramSocket s = new DatagramSocket();
        this.servidor = new InetSocketAddress(InetAddress.getByName(host), portaServidor);
        try {
            // Handshake com papel REQUISITANTE sem segredo, só registrador tem
            this.sessao = Handshake.estabelecer(s, servidor, Protocolo.PAPEL_REQUISITANTE, nome, "");
        } catch (IOException e) {
            s.close();
            throw e;
        }
        this.socket = s;

        // Thread que escuta respostas/notificações cifradas do DNS
        Thread ouvinte = new Thread(this::escutar, nome + "-ouvinte");
        ouvinte.setDaemon(true);
        ouvinte.start();

        enviarSeguro("REGISTER"); // passa a receber NOTIFY
    }

    public void resolver(String nomeServidor) {
        enviarSeguro("RESOLVE " + nomeServidor);
    }

    public Map<String, String> copiaDoCache() {
        return new TreeMap<>(cache);
    }

    public void fechar() {
        ativo = false;
        socket.close();
    }

    // Métodos de adulteração para o Caso 3 (falha de integridade) 

    // Altera 1 bit do HMAC -> servidor deve descartar por HMAC inválido
    public void adulterarHmac(String nomeServidor) {
        enviarAdulterado("RESOLVE " + nomeServidor, false);
    }

    // Altera 1 bit do texto cifrado -> HMAC não bate -> servidor descarta
    public void adulterarCifra(String nomeServidor) {
        enviarAdulterado("RESOLVE " + nomeServidor, true);
    }

    // Envia mensagem normal, cifrada na sessão
    private void enviarSeguro(String claro) {
        String pacote = sessao.empacotar(claro);
        Log.info(nome, "ENVIANDO [" + sessao.rotulo() + "] " + Sessao.resumo(pacote)
                + " | claro=\"" + claro + "\"");
        enviarBruto(pacote);
    }

    // Monta o pacote, corrompe 1 bit (no cifrado ou no HMAC) e envia
    private void enviarAdulterado(String claro, boolean adulterarCifra) {
        String[] p = sessao.empacotar(claro).split("\\|", -1);
        // Layout: DATA|id|iv|cifrado|hmac -> índices 3 (cifrado) e 4 (hmac)
        int campo = adulterarCifra ? 3 : 4;
        byte[] bytes = CriptoUtil.deb64(p[campo]);
        bytes[0] ^= 0x01; // XOR de 1 bit
        p[campo] = CriptoUtil.b64(bytes);
        Log.info(nome, "ENVIANDO PACOTE ADULTERADO (1 bit alterado no "
                + (adulterarCifra ? "texto cifrado" : "HMAC") + ") | claro original=\"" + claro
                + "\" | esperado: o DNS descartar o pacote");
        enviarBruto(String.join("|", p));
    }

    private void enviarBruto(String pacote) {
        byte[] dados = pacote.getBytes(StandardCharsets.UTF_8);
        try {
            socket.send(new DatagramPacket(dados, dados.length, servidor));
        } catch (IOException e) {
            Log.info(nome, "Falha ao enviar: " + e.getMessage());
        }
    }

    // Loop da thread ouvinte: só aceita DATA|... e valida HMAC
    private void escutar() {
        while (ativo) {
            DatagramPacket pacote = new DatagramPacket(
                    new byte[CriptoUtil.TAM_DATAGRAMA], CriptoUtil.TAM_DATAGRAMA);
            try {
                socket.receive(pacote);
            } catch (IOException e) {
                break; // socket fechado
            }
            String texto = new String(pacote.getData(), 0, pacote.getLength(),
                    StandardCharsets.UTF_8).trim();
            if (!texto.startsWith("DATA|")) {
                continue; // ignora PUBKEY residual etc....
            }
            try {
                String claro = sessao.abrir(texto); // valida HMAC e decifra
                Log.info(nome, "RECEBIDO [" + sessao.rotulo() + "] HMAC=OK "
                        + Sessao.resumo(texto) + " | claro=\"" + claro + "\"");
                interpretar(claro);
            } catch (FalhaIntegridadeException e) {
                // Defesa do cliente pacote do DNS com HMAC inválido é descartado
                Log.info(nome, "FALHA DE INTEGRIDADE: " + e.getMessage()
                        + " -> pacote DESCARTADO");
            }
        }
    }

    // Interpreta o texto claro recebido do DNS
    private void interpretar(String texto) {
        String[] t = texto.split("\\s+");
        if (t[0].equals("RESOLVIDO") && t.length == 3) {
            cache.put(t[1], t[2]);
            Log.info(nome, "Resposta do DNS (validada): " + t[1] + " -> " + t[2]);
        } else if (t[0].equals("NOTIFY") && t.length == 3) {
            // Binding dinâmico atualiza o cache local
            String antigo = cache.put(t[1], t[2]);
            Log.info(nome, "*** NOTIFICAÇÃO validada: " + t[1] + " mudou"
                    + (antigo != null ? " de " + antigo : " (nao estava no cache)")
                    + " para " + t[2] + " | tabela local atualizada");
        } else if (t[0].equals("REGISTRADO")) {
            Log.info(nome, "Registrado no servidor para receber atualizacoes");
        } else if (t[0].equals("DESREGISTRADO")) {
            Log.info(nome, "Desregistrado; não receberá mais atualizacoes");
        } else if (t[0].equals("ERRO")) {
            // Caso 3a: erro de entrada -> imprime a mensagem padronizada do PDF
            if (Protocolo.ehErroDeEntrada(texto)) {
                Log.info(nome, Protocolo.MSG_ERRO_ENTRADA
                        + " (servidor: " + texto.substring(4).trim() + ")");
            } else {
                Log.info(nome, "Erro do servidor: " + texto.substring(4).trim());
            }
        } else {
            Log.info(nome, "Mensagem desconhecida: \"" + texto + "\"");
        }
    }

    // Permite rodar o cliente como processo independente (requisito global)
    public static void main(String[] args) throws Exception {
        String nome = args.length > 0 ? args[0] : "C1";
        String host = args.length > 1 ? args[1] : "localhost";
        int porta = args.length > 2 ? Integer.parseInt(args[2]) : DnsServer.PORTA_PADRAO;

        ClienteRequisitante c;
        try {
            c = new ClienteRequisitante(nome, host, porta);
        } catch (IOException e) {
            System.out.println("Nao foi possivel estabelecer o canal seguro com o DNS: "
                    + e.getMessage());
            return;
        }

        System.out.println("Comandos: resolver <nome> | adulterar-hmac <nome> "
                + "| adulterar-cifra <nome> | cache | sair");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String linha;
        while ((linha = in.readLine()) != null) {
            linha = linha.trim();
            String[] t = linha.split("\\s+", 2);
            if (linha.equals("sair")) {
                break;
            } else if (linha.equals("cache")) {
                System.out.println(c.copiaDoCache());
            } else if (t.length == 2 && t[0].equals("resolver")) {
                c.resolver(t[1].trim());
            } else if (t.length == 2 && t[0].equals("adulterar-hmac")) {
                c.adulterarHmac(t[1].trim());
            } else if (t.length == 2 && t[0].equals("adulterar-cifra")) {
                c.adulterarCifra(t[1].trim());
            } else if (!linha.isEmpty()) {
                System.out.println(Protocolo.MSG_ERRO_ENTRADA + " (comando invalido)");
            }
        }
        c.fechar();
    }
}