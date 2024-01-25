package br.com.pamela.calendario.modules.event.useCases;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.time.LocalDateTime;
import java.util.stream.Collectors;
import br.com.pamela.calendario.modules.event.entities.EventEntity;
import br.com.pamela.calendario.modules.event.repositories.EventRepository;

@Service
public class GetEventsUseCase {
  @Autowired
  private EventRepository eventRepository;

  public List<EventEntity> execute(UUID userId, LocalDateTime startDate, LocalDateTime endDate) {
    Optional<List<EventEntity>> currentEvents = eventRepository.findByUserId(userId);

    if (currentEvents.isPresent()) {
      List<EventEntity> events = currentEvents.get();
      if (startDate != null) {
        events = events.stream()
            .filter(e -> e.getStartDateTime().isAfter(startDate) || e.getStartDateTime().isEqual(startDate))
            .collect(Collectors.toList());
      }

      if (endDate != null) {
        events = events.stream()
            .filter(e -> e.getEndDateTime().isBefore(endDate) || e.getEndDateTime().isEqual(endDate))
            .collect(Collectors.toList());
      }

      return events;
    } else {
      return Collections.emptyList();
    }
  }
}
