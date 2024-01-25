package br.com.pamela.calendario.exceptions;

public class EventNotFoundException extends RuntimeException {
  public EventNotFoundException() {
    super("Evento não encontrado");
  }
}
