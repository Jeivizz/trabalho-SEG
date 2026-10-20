package org.example.pratica1;

// Lançada quando um pacote recebido NÃO pode ser aceito: HMAC inválido
// (adulterado ou chave errada), formato malformado ou número de sequência
// repetido (replay). Quem captura esta exceção DESCARTA o pacote sem
// processá-lo e registra a falha no log (exigência do Caso 3).
public class FalhaIntegridadeException extends Exception {

    public FalhaIntegridadeException(String mensagem) {
        super(mensagem);
    }
}
