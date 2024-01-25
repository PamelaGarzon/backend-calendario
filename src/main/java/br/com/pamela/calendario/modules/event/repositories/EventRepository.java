package br.com.pamela.calendario.modules.event.repositories;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.time.LocalDateTime;

import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.stereotype.Repository;

import br.com.pamela.calendario.modules.event.entities.EventEntity;

@Repository
public interface EventRepository extends JpaRepository<EventEntity, UUID> {
  Optional<List<EventEntity>> findByUserId(UUID userId);

  Optional<List<EventEntity>> findByUserIdAndStartDateTimeEquals(UUID userId, LocalDateTime startDateTime);

  Optional<List<EventEntity>> findByUserIdAndStartDateTimeLessThanEqualAndEndDateTimeGreaterThanEqual(
      UUID userId, LocalDateTime startDateTime, LocalDateTime endDateTime);

  Optional<EventEntity> findByIdAndUserId(UUID id, UUID userId);

}
