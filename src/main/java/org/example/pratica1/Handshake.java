package org.example.pratica1;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;


public final class Handshake {

    public static final int TENTATIVAS = 3;   // retransmite se o UDP perder
    public static final int TIMEOUT_MS = 2000;

    private Handshake() {
    }

    public static Sessao estabelecer(DatagramSocket socket, InetSocketAddress servidor,
                                     String papel, String nome, String segredo) throws IOException {
        int timeoutOriginal = socket.getSoTimeout();
        socket.setSoTimeout(TIMEOUT_MS); // timeout temporário só para o handshake
        try {
            for (int t = 1; t <= TENTATIVAS; t++) {
                try {
                    return tentar(socket, servidor, papel, nome, segredo);
                } catch (SocketTimeoutException e) {
                    // UDP pode perder pacote: tenta de novo
                    Log.info(nome, "HANDSHAKE sem resposta do DNS (tentativa " + t + "/" + TENTATIVAS + ")");
                }
            }
            throw new IOException("handshake falhou: o servidor DNS nao respondeu");
        } finally {
            socket.setSoTimeout(timeoutOriginal); // restaura timeout original
        }
    }

    private static Sessao tentar(DatagramSocket socket, InetSocketAddress servidor,
                                 String papel, String nome, String segredo) throws IOException {
        try {
            // ETAPA 1: HELLO -> PUBKEY
            Log.info(nome, "HANDSHAKE 1/3 -> HELLO enviado ao DNS");
            enviar(socket, servidor, "HELLO");
            String resp = receber(socket);
            String[] p = resp.split("\\|", -1);
            if (p.length != 2 || !p[0].equals("PUBKEY")) {
                throw new IOException("resposta inesperada ao HELLO");
            }
            PublicKey chavePublica = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(CriptoUtil.deb64(p[1])));
            Log.info(nome, "HANDSHAKE 1/3 <- chave publica RSA recebida (SHA-256: "
                    + CriptoUtil.impressaoDigital(chavePublica) + ")");

            // ETAPA 2: gera AES+HMAC, monta blob e cifra com RSA-OAEP
            byte[] aes = CriptoUtil.aleatorios(CriptoUtil.TAM_CHAVE_AES);
            byte[] mac = CriptoUtil.aleatorios(CriptoUtil.TAM_CHAVE_MAC);
            byte[] idBytes = CriptoUtil.aleatorios(8); // id da sessão
            byte[] extra = (papel + ":" + nome + ":" + segredo).getBytes(StandardCharsets.UTF_8);

            // Layout do blob: [AES 32][MAC 32][id 8][papel:nome:segredo]
            byte[] blob = new byte[72 + extra.length];
            System.arraycopy(aes, 0, blob, 0, 32);
            System.arraycopy(mac, 0, blob, 32, 32);
            System.arraycopy(idBytes, 0, blob, 64, 8);
            System.arraycopy(extra, 0, blob, 72, extra.length);
            if (blob.length > 190) { // limite do RSA-2048/OAEP-SHA256
                throw new IOException("dados do handshake grandes demais (nome/segredo muito longos)");
            }

            Log.info(nome, "HANDSHAKE 2/3 -> chaves AES-256 e HMAC-SHA256 geradas; enviando KEYEX cifrado com RSA-OAEP");
            enviar(socket, servidor, "KEYEX|" + CriptoUtil.b64(CriptoUtil.rsaCifrar(chavePublica, blob)));

            // ETAPA 3: recebe KEYOK cifrado com a sessão recém-criada
            Sessao sessao = new Sessao(CriptoUtil.hex(idBytes), aes, mac, papel, nome, servidor);
            String conf = receber(socket);
            // ignora PUBKEY duplicado defesa contra reenvio, o timeout do socket evita loop infinito
            while (conf.startsWith("PUBKEY|")) {
            }
            String claro;
            try {
                claro = sessao.abrir(conf); // valida HMAC e decifra
            } catch (FalhaIntegridadeException e) {
                throw new IOException("confirmacao do servidor rejeitda: " + e.getMessage());
            }
            if (claro.startsWith("ERRO")) {
                throw new IOException("servidor recusou o handshake: " + claro);
            }
            if (!claro.equals("KEYOK")) {
                throw new IOException("confirmacao inesperada: " + claro);
            }
            Log.info(nome, "HANDSHAKE 3/3 <- KEYOK recebido, HMAC validado. Canal seguro estabelecido ("
                    + sessao.rotulo() + ", papel " + papel + ")");
            return sessao;

        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException("falha criptografica no handshake: " + e.getMessage(), e);
        }
    }

    private static void enviar(DatagramSocket socket, InetSocketAddress destino, String texto) throws IOException {
        byte[] dados = texto.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, destino));
    }

    private static String receber(DatagramSocket socket) throws IOException {
        DatagramPacket pacote = new DatagramPacket(new byte[CriptoUtil.TAM_DATAGRAMA], CriptoUtil.TAM_DATAGRAMA);
        socket.receive(pacote);
        return new String(pacote.getData(), 0, pacote.getLength(), StandardCharsets.UTF_8).trim();
    }
}