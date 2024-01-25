package br.com.pamela.calendario.modules.event.useCases;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.pamela.calendario.exceptions.EventConflictException;
import br.com.pamela.calendario.exceptions.UserNotFoundException;
import br.com.pamela.calendario.modules.event.entities.EventEntity;
import br.com.pamela.calendario.modules.event.repositories.EventRepository;
import br.com.pamela.calendario.modules.user.repositories.UserRepository;

@Service
public class CreateEventUseCase {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private EventRepository eventRepository;

  public EventEntity execute(EventEntity eventEntity) {
    userRepository
        .findById(eventEntity.getUserId())
        .orElseThrow(() -> {
          throw new UserNotFoundException();
        });

    LocalDateTime startDateTime = eventEntity.getStartDateTime();
    LocalDateTime endDateTime = eventEntity.getEndDateTime();

    if (eventRepository.findByUserIdAndStartDateTimeEquals(eventEntity.getUserId(), startDateTime)
        .map(existingEvents -> existingEvents.stream()
            .anyMatch(existingEvent -> existingEvent.getEndDateTime().isAfter(startDateTime)
                || existingEvent.getEndDateTime().isEqual(startDateTime)))
        .orElse(false)) {
      throw new EventConflictException();
    }

    if (eventRepository.findByUserIdAndStartDateTimeLessThanEqualAndEndDateTimeGreaterThanEqual(
        eventEntity.getUserId(), endDateTime, startDateTime)
        .map(existingEvents -> existingEvents.stream()
            .anyMatch(existingEvent -> existingEvent.getEndDateTime().isAfter(startDateTime)
                || existingEvent.getEndDateTime().isEqual(startDateTime)))
        .orElse(false)) {
      throw new EventConflictException();
    }
    return this.eventRepository.save(eventEntity);
  }
}
