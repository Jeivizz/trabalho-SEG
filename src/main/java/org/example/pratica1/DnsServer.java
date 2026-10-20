package org.example.pratica1;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

// QUESTÃO 1 (Segurança) - Mini-DNS UDP com criptografia híbrida.
//
// Datagramas aceitos em claro (só o handshake):
//   HELLO                -> responde PUBKEY|<chave pública RSA>
//   KEYEX|<RSA(chaves)>  -> cria a sessão e responde KEYOK (já cifrado)
// Qualquer outro datagrama precisa ser DATA|... válido, senão é DESCARTADO.
//
// Mensagens de aplicação (dentro do DATA, já decifradas):
//   REGISTER / UNREGISTER      |  RESOLVE <nome>  |  UPDATE <nome> <ip>
//   Respostas: REGISTRADO, DESREGISTRADO, RESOLVIDO <nome> <ip>,
//              ATUALIZADO <nome> <ip>, NOTIFY <nome> <ip>, ERRO <CODIGO> ...
public class DnsServer {

    public static final int PORTA_PADRAO = 5300; // 5353 é usada pelo mDNS em muitos SOs
    public static final String SEGREDO_PADRAO = "registrador123";
    private static final int MAX_SESSOES = 1000; // evita exaustão de memória por handshakes falsos

    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
    private static final Pattern NOME_VALIDO = Pattern.compile("^servidor[1-9][0-9]{0,8}$");
    private static final Pattern NOME_CLIENTE = Pattern.compile("^[A-Za-z0-9_-]{1,16}$");

    private final DatagramSocket socket;
    private final KeyPair parRsa;              // chave privada NUNCA sai deste processo
    private final String chavePublicaB64;
    private final byte[] segredoRegistrador;

    // nome -> endereço (mesmo mapa da versão original)
    private final Map<String, String> tabela = new ConcurrentHashMap<>();
    // idSessao -> sessão (chaves AES/HMAC de cada cliente)
    private final Map<String, Sessao> sessoes = new ConcurrentHashMap<>();

    private final ExecutorService pool;
    private volatile boolean ativo = true;

    public DnsServer(int porta, String segredoRegistrador) throws Exception {
        this.socket = new DatagramSocket(porta);
        this.segredoRegistrador = segredoRegistrador.getBytes(StandardCharsets.UTF_8);
        this.parRsa = CriptoUtil.gerarParRsa();
        this.chavePublicaB64 = CriptoUtil.b64(parRsa.getPublic().getEncoded());

        // Carga inicial exigida pela questão: servidor1 -> 192.168.0.10 ... servidor10 -> 192.168.0.100
        for (int i = 1; i <= 10; i++) {
            tabela.put("servidor" + i, "192.168.0." + (i * 10));
        }
        this.pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
    }

    // Laço principal: só recebe datagramas; o tratamento é feito pelo pool.
    public void executar() {
        Log.info("DNS", "Mini-DNS seguro escutando em UDP/" + socket.getLocalPort()
                + " | RSA-2048 gerado (SHA-256: " + CriptoUtil.impressaoDigital(parRsa.getPublic()) + ")");
        while (ativo) {
            DatagramPacket pacote = new DatagramPacket(new byte[CriptoUtil.TAM_DATAGRAMA], CriptoUtil.TAM_DATAGRAMA);
            try {
                socket.receive(pacote);
            } catch (IOException e) {
                if (ativo) {
                    Log.info("DNS", "Erro de E/S ao receber: " + e.getMessage());
                }
                break;
            }
            pool.execute(() -> tratar(pacote));
        }
    }

    public void parar() {
        ativo = false;
        socket.close();
    }

    // Despacha pelo "tipo" do datagrama. Qualquer exceção inesperada é capturada
    // aqui: um pacote ruim nunca derruba o servidor.
    private void tratar(DatagramPacket pacote) {
        try {
            String texto = new String(pacote.getData(), pacote.getOffset(), pacote.getLength(),
                    StandardCharsets.UTF_8).trim();
            SocketAddress remetente = pacote.getSocketAddress();

            if (texto.equals("HELLO")) {
                tratarHello(remetente);
            } else if (texto.startsWith("KEYEX|")) {
                tratarKeyex(texto, remetente);
            } else if (texto.startsWith("DATA|")) {
                tratarDados(texto, remetente);
            } else {
                Log.info("DNS", "Datagrama desconhecido/nao cifrado de " + remetente + " DESCARTADO");
            }
        } catch (RuntimeException e) {
            Log.info("DNS", "Erro inesperado ao tratar pacote (descartado): " + e);
        }
    }

    // ------------------------------------------------------------------
    // Handshake
    // ------------------------------------------------------------------

    private void tratarHello(SocketAddress remetente) {
        Log.info("DNS", "HANDSHAKE <- HELLO de " + remetente + " | enviando chave publica RSA");
        enviarBruto("PUBKEY|" + chavePublicaB64, remetente);
    }

    private void tratarKeyex(String texto, SocketAddress remetente) {
        try {
            String[] p = texto.split("\\|", -1);
            if (p.length != 2) {
                throw new IllegalArgumentException("formato");
            }
            // Só a chave PRIVADA do servidor consegue abrir este bloco.
            byte[] blob = CriptoUtil.rsaDecifrar(parRsa.getPrivate(), CriptoUtil.deb64(p[1]));
            if (blob.length < 73) {
                throw new IllegalArgumentException("bloco curto");
            }
            byte[] aes = Arrays.copyOfRange(blob, 0, 32);
            byte[] mac = Arrays.copyOfRange(blob, 32, 64);
            String id = CriptoUtil.hex(Arrays.copyOfRange(blob, 64, 72));
            String[] extra = new String(blob, 72, blob.length - 72, StandardCharsets.UTF_8).split(":", 3);
            if (extra.length != 3) {
                throw new IllegalArgumentException("identificacao");
            }
            String papel = extra[0];
            String nome = extra[1];
            String segredo = extra[2];

            boolean papelValido = papel.equals(Protocolo.PAPEL_REQUISITANTE) || papel.equals(Protocolo.PAPEL_REGISTRADOR);
            if (!papelValido || !NOME_CLIENTE.matcher(nome).matches()) {
                throw new IllegalArgumentException("papel/nome invalido");
            }

            // Autorização: só quem conhece o segredo pode agir como REGISTRADOR.
            // Simplificado: descarta o KEYEX sem responder nada. O cliente vai
            // cair no timeout do handshake e reportar erro.
            if (papel.equals(Protocolo.PAPEL_REGISTRADOR)
                    && !CriptoUtil.iguais(segredo.getBytes(StandardCharsets.UTF_8), segredoRegistrador)) {
                Log.info("DNS", "HANDSHAKE: " + nome + " pediu papel REGISTRADOR com segredo INCORRETO -> DESCARTADO");
                return;
            }
            if (sessoes.size() >= MAX_SESSOES) {
                Log.info("DNS", "HANDSHAKE recusado: limite de sessoes atingido");
                return;
            }
            Sessao sessao = new Sessao(id, aes, mac, papel, nome, remetente);
            // putIfAbsent: um KEYEX repetido não cria sessão duplicada.
            if (sessoes.putIfAbsent(id, sessao) != null) {
                Log.info("DNS", "HANDSHAKE: KEYEX repetido (idSessao ja existe) DESCARTADO");
                return;
            }
            Log.info("DNS", "HANDSHAKE <- KEYEX de " + remetente + ": chaves AES/HMAC decifradas com a chave privada RSA | "
                    + sessao.rotulo() + " criada (papel " + papel + ")");
            enviar(sessao, "KEYOK");

        } catch (Exception e) { // RSA inválido, Base64 ruim, campos faltando...
            Log.info("DNS", "HANDSHAKE: KEYEX invalido de " + remetente + " DESCARTADO ("
                    + e.getClass().getSimpleName() + ")");
        }
    }

    // ------------------------------------------------------------------
    // Mensagens de aplicação (cifradas)
    // ------------------------------------------------------------------

    private void tratarDados(String texto, SocketAddress remetente) {
        String id = Sessao.extrairId(texto);
        Sessao sessao = id == null ? null : sessoes.get(id);
        if (sessao == null) {
            Log.info("DNS", "FALHA: pacote de " + remetente + " com sessao desconhecida/malformado -> DESCARTADO");
            return;
        }

        String claro;
        try {
            claro = sessao.abrir(texto); // valida HMAC, depois decifra
        } catch (FalhaIntegridadeException e) {
            // Exigência do Caso 3: descarta sem processar e registra no log.
            Log.info("DNS", "FALHA DE INTEGRIDADE [" + sessao.rotulo() + "] de " + remetente + ": "
                    + e.getMessage() + " -> pacote UDP DESCARTADO sem processar");
            return;
        }

        sessao.endereco = remetente; // pacote autenticado: atualiza para onde enviar NOTIFY
        Log.info("DNS", "RECEBIDO [" + sessao.rotulo() + "] HMAC=OK " + Sessao.resumo(texto)
                + " | claro=\"" + claro + "\"");
        processar(sessao, claro);
    }

    private void processar(Sessao s, String claro) {
        String[] t = claro.trim().split("\\s+");
        switch (t[0].toUpperCase()) {
            case "REGISTER":
                s.notificar = true; // passa a receber NOTIFY cifrado
                enviar(s, "REGISTRADO");
                break;

            case "UNREGISTER":
                s.notificar = false;
                enviar(s, "DESREGISTRADO");
                break;

            case "RESOLVE":
                resolver(s, t);
                break;

            case "UPDATE":
                atualizar(s, t);
                break;

            default:
                rejeitar(s, "REQUISICAO_INVALIDA");
        }
    }

    private void resolver(Sessao s, String[] t) {
        if (t.length != 2) {
            rejeitar(s, "REQUISICAO_INVALIDA");
            return;
        }
        String nome = t[1].toLowerCase();
        if (!NOME_VALIDO.matcher(nome).matches()) {
            rejeitar(s, "FORMATO_INVALIDO " + t[1]);
            return;
        }
        String ip = tabela.get(nome);
        if (ip == null) {
            rejeitar(s, "NAO_ENCONTRADO " + nome);
            return;
        }
        enviar(s, "RESOLVIDO " + nome + " " + ip);
    }

    // Binding dinâmico: valida, atualiza a tabela e propaga NOTIFY CIFRADO,
    // cada um com as chaves da sessão do destinatário.
    private void atualizar(Sessao s, String[] t) {
        if (!s.papel.equals(Protocolo.PAPEL_REGISTRADOR)) {
            Log.info("DNS", "UPDATE negado: [" + s.rotulo() + "] nao e REGISTRADOR");
            rejeitar(s, "NAO_AUTORIZADO");
            return;
        }
        if (t.length != 3) {
            rejeitar(s, "REQUISICAO_INVALIDA");
            return;
        }
        String nome = t[1].toLowerCase();
        String novoIp = t[2];
        if (!NOME_VALIDO.matcher(nome).matches()) {
            rejeitar(s, "FORMATO_INVALIDO " + t[1]);
            return;
        }
        if (!tabela.containsKey(nome)) {
            rejeitar(s, "NAO_ENCONTRADO " + nome);
            return;
        }
        if (!IPV4.matcher(novoIp).matches()) {
            rejeitar(s, "IP_INVALIDO " + novoIp);
            return;
        }

        String antigo = tabela.put(nome, novoIp);
        Log.info("DNS", "ATUALIZADO " + nome + ": " + antigo + " -> " + novoIp);
        enviar(s, "ATUALIZADO " + nome + " " + novoIp);

        int total = 0;
        for (Sessao dest : sessoes.values()) {
            if (dest.notificar) {
                total++;
            }
        }
        Log.info("DNS", "Propagando NOTIFY cifrado para " + total + " requisitante(s) registrado(s)");
        for (Sessao dest : sessoes.values()) {
            if (dest.notificar) {
                enviar(dest, "NOTIFY " + nome + " " + novoIp);
            }
        }
    }

    // Entrada inválida: imprime a mensagem exigida no log e responde ERRO cifrado.
    private void rejeitar(Sessao s, String motivo) {
        Log.info("DNS", Protocolo.MSG_ERRO_ENTRADA + " [" + s.rotulo() + " | motivo: " + motivo + "]");
        enviar(s, "ERRO " + motivo);
    }

    // ------------------------------------------------------------------
    // Envio
    // ------------------------------------------------------------------

    private void enviar(Sessao s, String claro) {
        SocketAddress destino = s.endereco;
        if (destino == null) {
            return;
        }
        String pacote = s.empacotar(claro);
        Log.info("DNS", "ENVIANDO [" + s.rotulo() + "] " + Sessao.resumo(pacote) + " | claro=\"" + claro + "\"");
        enviarBruto(pacote, destino);
    }

    private void enviarBruto(String texto, SocketAddress destino) {
        byte[] dados = texto.getBytes(StandardCharsets.UTF_8);
        try {
            socket.send(new DatagramPacket(dados, dados.length, destino));
        } catch (IOException e) {
            Log.info("DNS", "Falha ao enviar para " + destino + ": " + e.getMessage());
        }
    }

    // java DnsServer [porta] [segredoDoRegistrador]
    public static void main(String[] args) throws Exception {
        int porta = args.length > 0 ? Integer.parseInt(args[0]) : PORTA_PADRAO;
        String segredo = args.length > 1 ? args[1] : SEGREDO_PADRAO;
        new DnsServer(porta, segredo).executar();
    }
}