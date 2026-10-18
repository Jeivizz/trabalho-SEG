package org.example.pratica2;

import org.example.pratica2.impl.ImplCliente;

public class Cliente {
    String idCliente;
    String operacao;
    String entradaBruta;

    public Cliente(String idCliente, String operacao, String entradaBruta) {
        this.idCliente = idCliente;
        this.operacao = operacao;
        this.entradaBruta = entradaBruta;
        this.rodar();
    }


    // Inicia o objeto ImplCliente e a Thread
    private void rodar() {
        ImplCliente cliente = new ImplCliente(idCliente, operacao, entradaBruta);
        Thread t = new Thread(cliente);
        t.start();
    }

    public static void main(String[] args) {
        System.out.println("=================================================================================");
        new Cliente("Cliente 1", "SOMA", "10 5");
        new Cliente("Cliente 2", "MULTIPLICACAO", "4 3");
        new Cliente("Cliente 3", "DIVISAO", "20 4");

        try { Thread.sleep(500); } catch (InterruptedException e) {}
        System.out.println("\n============================= TESTES DE EXCEÇÃO ===============================");

        new Cliente("Cliente Erro 1", "DIVISAO", "10 0");
        new Cliente("Cliente Erro 2", "SOMA", "dez 5");
    }
}