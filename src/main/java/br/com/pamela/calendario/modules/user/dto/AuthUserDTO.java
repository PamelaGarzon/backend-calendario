package br.com.pamela.calendario.modules.user.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthUserDTO {

  @Schema(example = "pamela@gmail.com")
  private String email;
  private UUID id;

  @Schema(example = "12345678")
  private String password;

}
