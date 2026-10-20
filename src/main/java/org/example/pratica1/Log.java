package org.example.pratica1;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

public final class Log {

    // Timestamp com milissegundos: essencial para mostrar a ordem
    // handshake -> envio -> recebimento -> validação HMAC na gravação
    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private Log() {
    }

    // Log padronizado: [hora] [origem] texto
    public static void info(String origem, String texto) {
        System.out.println("[" + LocalTime.now().format(HORA) + "] [" + origem + "] " + texto);
    }
}