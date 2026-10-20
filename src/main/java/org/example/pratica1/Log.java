package org.example.pratica1;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

// Log único para todos os processos: "[hora] [origem] mensagem".
// Cada processo (DNS, C1, C2, Registrador...) imprime no PRÓPRIO console;
// por isso os logs de "ambos os lados" aparecem em terminais diferentes.
public final class Log {

    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private Log() {
    }

    public static void info(String origem, String texto) {
        System.out.println("[" + LocalTime.now().format(HORA) + "] [" + origem + "] " + texto);
    }
}
