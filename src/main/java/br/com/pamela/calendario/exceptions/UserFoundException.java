package br.com.pamela.calendario.exceptions;

public class UserFoundException extends RuntimeException {
  public UserFoundException() {
    super("Usuário ja existe");
  }
}
