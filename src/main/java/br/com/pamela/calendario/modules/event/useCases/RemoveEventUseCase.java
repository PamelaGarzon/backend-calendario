package br.com.pamela.calendario.modules.event.useCases;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.pamela.calendario.exceptions.EventNotFoundException;
import br.com.pamela.calendario.modules.event.repositories.EventRepository;

@Service
public class RemoveEventUseCase {
  @Autowired
  private EventRepository eventRepository;

  public void execute(UUID userId, UUID eventId) {
    eventRepository.findByIdAndUserId(eventId, userId)
        .ifPresentOrElse(
            eventRepository::delete,
            () -> {
              throw new EventNotFoundException();
            });
  }
}
