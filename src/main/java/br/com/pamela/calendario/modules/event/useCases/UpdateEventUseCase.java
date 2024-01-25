package br.com.pamela.calendario.modules.event.useCases;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.pamela.calendario.exceptions.EventNotFoundException;
import br.com.pamela.calendario.modules.event.entities.EventEntity;
import br.com.pamela.calendario.modules.event.repositories.EventRepository;

@Service
public class UpdateEventUseCase {

  @Autowired
  private EventRepository eventRepository;

  public EventEntity execute(UUID userId, UUID eventId, LocalDateTime startDateTime, LocalDateTime endDateTime,
      String description) {
    EventEntity currentEvent = eventRepository.findByIdAndUserId(eventId, userId)
        .orElseThrow(EventNotFoundException::new);

    currentEvent.setStartDateTime(startDateTime);
    currentEvent.setEndDateTime(endDateTime);
    currentEvent.setDescription(description);
    return eventRepository.save(currentEvent);
  }

}
