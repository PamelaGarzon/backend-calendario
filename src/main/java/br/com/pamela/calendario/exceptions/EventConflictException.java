package br.com.pamela.calendario.exceptions;

public class EventConflictException extends RuntimeException {
  public EventConflictException() {
    super("Este evento se sobrepõe a outro evento existente.");
  }
}
