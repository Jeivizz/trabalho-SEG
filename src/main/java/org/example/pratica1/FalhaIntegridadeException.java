package org.example.pratica1;

// Exceção lançada quando um pacote recebido NÃO pode ser aceito:
// HMAC inválido, formato malformado ou IV com tamanho errado
// Quem captura descarta o pacote sem processar e loga a falha
// É "checked" de propósito: força o chamador a tratar
public class FalhaIntegridadeException extends Exception {

    public FalhaIntegridadeException(String mensagem) {
        super(mensagem);
    }
}