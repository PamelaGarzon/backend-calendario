package br.com.pamela.calendario.modules.event.entities;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;
import org.springframework.format.annotation.DateTimeFormat;

import com.fasterxml.jackson.annotation.JsonIgnore;

import br.com.pamela.calendario.modules.user.entities.UserEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import java.sql.Timestamp;

@Entity(name = "Evento")
@Data
public class EventEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @NotNull(message = "A descrição não pode ser nula")
  private String description;

  @NotNull(message = "Campo obrigatorio")
  @Future(message = "A data de início não pode ser uma data passada.")
  @DateTimeFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
  private LocalDateTime startDateTime;

  @NotNull(message = "Campo obrigatorio")
  @Future(message = "A data de término não pode ser uma data passada.")
  @DateTimeFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
  private LocalDateTime endDateTime;

  @ManyToOne()
  @JoinColumn(name = "user_id", insertable = false, updatable = false)
  @JsonIgnore
  private UserEntity userEntity;

  @Column(name = "user_id", nullable = false)
  private UUID userId;

  @JsonIgnore
  @CreationTimestamp
  private Timestamp createAt;
}