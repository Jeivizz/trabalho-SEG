package org.example.pratica2;

import org.example.pratica2.impl.ImplCliente;



import java.io.PrintStream;
import java.net.ConnectException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;

public class Cliente {
    String idCliente, operacao, entradaBruta;
    boolean forcarFalhaHmac;

    public Cliente(String idCliente, String operacao, String entradaBruta, boolean forcarFalhaHmac) {
        this.idCliente = idCliente;
        this.operacao = operacao;
        this.entradaBruta = entradaBruta;
        this.forcarFalhaHmac = forcarFalhaHmac;
        this.rodar();
    }

    private void rodar() {
        new Thread(new ImplCliente(idCliente, operacao, entradaBruta, forcarFalhaHmac)).start();
    }

    public static void main(String[] args) throws InterruptedException {

        System.out.println("=== CASO 1 e CASO 2: Descoberta de Servico e Chamada com Load Balancing (AES+HMAC) ===");
        new Cliente("C1", "SOMA", "10 20", false);
        Thread.sleep(100);
        new Cliente("C2", "MULTIPLICACAO", "5 4", false);

        Thread.sleep(1000);
        System.out.println("\n=== CASO 3: Serviço Inválido e Falha de Integridade ===");
        new Cliente("C3_Invalido", "MODULO", "10 2", false);
        Thread.sleep(100);
        new Cliente("C3_Corrompido", "SOMA", "10 10", true);
    }
}

