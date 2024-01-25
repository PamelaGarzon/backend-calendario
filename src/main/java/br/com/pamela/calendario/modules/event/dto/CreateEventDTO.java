package br.com.pamela.calendario.modules.event.dto;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.media.Schema.RequiredMode;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.FutureOrPresent;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateEventDTO {

  @Schema
  private UUID userId;

  @Schema(example = "evento de Treinamento full stack", requiredMode = RequiredMode.REQUIRED)
  private String description;

  @Schema(example = "2024-01-22T12:00:00", requiredMode = RequiredMode.REQUIRED)
  @FutureOrPresent(message = "A data de inicio nao pode ser maior que a data final")
  private LocalDateTime startDateTime;

  @Schema(example = "2024-01-23T15:30:00", requiredMode = RequiredMode.REQUIRED)
  @Future(message = "A data de término deve ser no futuro")
  private LocalDateTime endDateTime;

}
