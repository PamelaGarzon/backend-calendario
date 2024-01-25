package br.com.pamela.calendario.exceptions;

public class UserInvalidLoginException extends RuntimeException {
  public UserInvalidLoginException() {
    super("Email/senha incorretos");
  }
}
