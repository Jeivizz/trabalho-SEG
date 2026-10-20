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

public class DnsServer {

    public static final int PORTA_PADRAO = 5300; // evita conflito com mDNS 5353 (ja vi 4 pessoas com o mesmo erro XD)
    public static final String SEGREDO_PADRAO = "registrador123"; // só o registrador conhece
    private static final int MAX_SESSOES = 1000; // mitigação simples de DoS

    // Validações de entrada
    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
    private static final Pattern NOME_VALIDO = Pattern.compile("^servidor[1-9][0-9]{0,8}$");
    private static final Pattern NOME_CLIENTE = Pattern.compile("^[A-Za-z0-9_-]{1,16}$");

    private final DatagramSocket socket;
    private final KeyPair parRsa;        // chave RSA do servidor (assimétrica)
    private final String chavePublicaB64; // enviada no HELLO
    private final byte[] segredoRegistrador; // comparado no handshake

    private final Map<String, String> tabela = new ConcurrentHashMap<>(); // nome -> IP
    private final Map<String, Sessao> sessoes = new ConcurrentHashMap<>(); // id -> sessão

    private final ExecutorService pool;
    private volatile boolean ativo = true;

    public DnsServer(int porta, String segredoRegistrador) throws Exception {
        this.socket = new DatagramSocket(porta);
        this.segredoRegistrador = segredoRegistrador.getBytes(StandardCharsets.UTF_8);
        this.parRsa = CriptoUtil.gerarParRsa(); // gera RSA-2048 na inicialização
        this.chavePublicaB64 = CriptoUtil.b64(parRsa.getPublic().getEncoded());

        // Carga inicial exigida: servidor
        // "servidor1" → "192.168.0.10"
        // "servidor2" → "192.168.0.20"
        // "servidor3" → "192.168.0.30"
        // "servidor4" → "192.168.0.40"
        // "servidor5" → "192.168.0.50"
        // "servidor6" → "192.168.0.60"
        // "servidor7" → "192.168.0.70"
        // "servidor8" → "192.168.0.80"
        // "servidor9" → "192.168.0.90"
        // "servidor10" → "192.168.0.100"

        for (int i = 1; i <= 10; i++) {
            tabela.put("servidor" + i, "192.168.0." + (i * 10));
        }
        this.pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
    }

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
            pool.execute(() -> tratar(pacote)); // cada pacote em uma thread
        }
    }

    public void parar() {
        ativo = false;
        socket.close();
    }

        // Despacha: HELLO -> handshake; KEYEX -> handshake; DATA -> mensagem cifrada
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
                // Pacote em texto claro ou com formato desconhecido: descarta.
                // Isso cobre o Caso 3 (mensagem sem cifra/HMAC não é processada).
                Log.info("DNS", "Datagrama desconhecido/nao cifrado de " + remetente + " DESCARTADO");
            }
        } catch (RuntimeException e) {
            // Defesa em profundidade: erro inesperado não derruba o servidor
            Log.info("DNS", "Erro inesperado ao tratar pacote (descartado): " + e);
        }
    }

    // HANDSHAKE 

    // Etapa 1: responde ao HELLO com a chave pública RSA
    private void tratarHello(SocketAddress remetente) {
        Log.info("DNS", "HANDSHAKE <- HELLO de " + remetente + " | enviando chave publica RSA");
        enviarBruto("PUBKEY|" + chavePublicaB64, remetente);
    }

    // Etapa 2: decifra o blob KEYEX com a chave privada RSA.
    // O blob contém: AES(32) + HMAC(32) + idSessao(8) + "papel:nome:segredo".
    // Valida papel, nome e segredo (só REGISTRADOR precisa de segredo correto).
    private void tratarKeyex(String texto, SocketAddress remetente) {
        try {
            String[] p = texto.split("\\|", -1);
            if (p.length != 2) {
                throw new IllegalArgumentException("formato");
            }

            // Decifra com RSA-OAEP só o servidor tem a chave privada
            byte[] blob = CriptoUtil.rsaDecifrar(parRsa.getPrivate(), CriptoUtil.deb64(p[1]));
            if (blob.length < 73) { // 32 AES + 32 MAC + 8 id + 1 separador mínimo
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

            // Valida papel e nome do cliente
            boolean papelValido = papel.equals(Protocolo.PAPEL_REQUISITANTE) || papel.equals(Protocolo.PAPEL_REGISTRADOR);
            if (!papelValido || !NOME_CLIENTE.matcher(nome).matches()) {
                throw new IllegalArgumentException("papel/nome invalido");
            }

            // Autorização: REGISTRADOR precisa apresentar o segredo correto.
            // Comparação em TEMPO CONSTANTE (CriptoUtil.iguais) evita timing attack.
            if (papel.equals(Protocolo.PAPEL_REGISTRADOR)
                    && !CriptoUtil.iguais(segredo.getBytes(StandardCharsets.UTF_8), segredoRegistrador)) {
                Log.info("DNS", "HANDSHAKE: " + nome + " pediu papel REGISTRADOR com segredo INCORRETO -> DESCARTADO");
                return;
            }
            // Limite de sessões mitigação básica de DoS
            if (sessoes.size() >= MAX_SESSOES) {
                Log.info("DNS", "HANDSHAKE recusado: limite de sessoes atingido");
                return;
            }
            Sessao sessao = new Sessao(id, aes, mac, papel, nome, remetente);
            // putIfAbsent: se o id já existe (KEYEX repetido), descarta
            if (sessoes.putIfAbsent(id, sessao) != null) {
                Log.info("DNS", "HANDSHAKE: KEYEX repetido (idSessao ja existe) DESCARTADO");
                return;
            }
            Log.info("DNS", "HANDSHAKE <- KEYEX de " + remetente + ": chaves AES/HMAC decifradas com a chave privada RSA | "
                    + sessao.rotulo() + " criada (papel " + papel + ")");
            // Etapa 3: confirma com KEYOK cifrado na sessão recém-criada
            enviar(sessao, "KEYOK");

        } catch (Exception e) { // qualquer falha criptográfica/format invalida o KEYEX
            Log.info("DNS", "HANDSHAKE: KEYEX invalido de " + remetente + " DESCARTADO ("
                    + e.getClass().getSimpleName() + ")");
        }
    }

    // MENSAGENS CIFRADA 

    // Recebe um DATA|..., acha a sessão pelo id, valida HMAC e decifra.
    // Se a sessão não existe ou o HMAC falha, DESCARTA sem processar (Caso 3).
    private void tratarDados(String texto, SocketAddress remetente) {
        String id = Sessao.extrairId(texto);
        Sessao sessao = id == null ? null : sessoes.get(id);
        if (sessao == null) {
            Log.info("DNS", "FALHA: pacote de " + remetente + " com sessao desconhecida/malformado -> DESCARTADO");
            return;
        }

        String claro;
        try {
            claro = sessao.abrir(texto); // valida HMAC (tempo constante) e decifra
        } catch (FalhaIntegridadeException e) {
            //  Caso 3 do PDF: HMAC corrompido -> descarta e registra falha 
            Log.info("DNS", "FALHA DE INTEGRIDADE [" + sessao.rotulo() + "] de " + remetente + ": "
                    + e.getMessage() + " -> pacote UDP DESCARTADO sem processar");
            return;
        }

        // UDP é sem conexão: aprende/atualiza o endereço atual do cliente
        // necessário para o servidor saber para onde enviar NOTIFY depois
        sessao.endereco = remetente;
        Log.info("DNS", "RECEBIDO [" + sessao.rotulo() + "] HMAC=OK " + Sessao.resumo(texto)
                + " | claro=\"" + claro + "\"");
        processar(sessao, claro);
    }

    // Interpreta o comando em texto claro já validado/decifrado
    private void processar(Sessao s, String claro) {
        String[] t = claro.trim().split("\\s+");
        switch (t[0].toUpperCase()) {
            case "REGISTER":
                s.notificar = true; // passa a receber NOTIFY em updates
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

    // Resolução de nome: RESOLVE <nome> -> RESOLVIDO <nome> <ip>
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
            // Caso 3a: nome inexistente (ex.: servidor99)
            rejeitar(s, "NAO_ENCONTRADO " + nome);
            return;
        }
        enviar(s, "RESOLVIDO " + nome + " " + ip);
    }

    // Atualização de IP (binding dinâmico) + NOTIFY cifrado para requisitantes
    private void atualizar(Sessao s, String[] t) {
        // Autorização: só o REGISTRADOR pode atualizar
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

        // Atualiza o mapa (put retorna o valor antigo para o log)
        String antigo = tabela.put(nome, novoIp);
        Log.info("DNS", "ATUALIZADO " + nome + ": " + antigo + " -> " + novoIp);
        enviar(s, "ATUALIZADO " + nome + " " + novoIp);

        // BINDING DINÂMICO: propaga NOTIFY cifrado a todos os registrados 
        int total = 0;
        for (Sessao dest : sessoes.values()) {
            if (dest.notificar) {
                total++;
            }
        }
        Log.info("DNS", "Propagando NOTIFY cifrado para " + total + " requisitante(s) registrado(s)");
        for (Sessao dest : sessoes.values()) {
            if (dest.notificar) {
                enviar(dest, "NOTIFY " + nome + " " + novoIp); // cada NOTIFY é cifrado na sessão do cliente
            }
        }
    }

    // Rejeita uma requisição inválida: loga a mensagem padronizada e responde ERRO <motivo>
    private void rejeitar(Sessao s, String motivo) {
        Log.info("DNS", Protocolo.MSG_ERRO_ENTRADA + " [" + s.rotulo() + " | motivo: " + motivo + "]");
        enviar(s, "ERRO " + motivo);
    }


    // Envia um texto claro cifrado na sessão (empacota com AES+HMAC)
    private void enviar(Sessao s, String claro) {
        SocketAddress destino = s.endereco;
        if (destino == null) {
            return; // sessão ainda sem endereço conhecido
        }
        String pacote = s.empacotar(claro);
        Log.info("DNS", "ENVIANDO [" + s.rotulo() + "] " + Sessao.resumo(pacote) + " | claro=\"" + claro + "\"");
        enviarBruto(pacote, destino);
    }

    // Envia bytes crus via UDP usado no PUBKEY e nos pacotes já cifrados
    private void enviarBruto(String texto, SocketAddress destino) {
        byte[] dados = texto.getBytes(StandardCharsets.UTF_8);
        try {
            socket.send(new DatagramPacket(dados, dados.length, destino));
        } catch (IOException e) {
            Log.info("DNS", "Falha ao enviar para " + destino + ": " + e.getMessage());
        }
    }

    // Permite rodar o DNS como processo independente 
    public static void main(String[] args) throws Exception {
        int porta = args.length > 0 ? Integer.parseInt(args[0]) : PORTA_PADRAO;
        String segredo = args.length > 1 ? args[1] : SEGREDO_PADRAO;
        new DnsServer(porta, segredo).executar();
    }
}