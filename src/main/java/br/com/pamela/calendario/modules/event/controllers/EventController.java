package br.com.pamela.calendario.modules.event.controllers;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.com.pamela.calendario.exceptions.EventNotFoundException;
import br.com.pamela.calendario.modules.event.dto.UpdateEventDTO;
import br.com.pamela.calendario.modules.event.entities.EventEntity;
import br.com.pamela.calendario.modules.event.useCases.CreateEventUseCase;
import br.com.pamela.calendario.modules.event.useCases.GetEventsUseCase;
import br.com.pamela.calendario.modules.event.useCases.RemoveEventUseCase;
import br.com.pamela.calendario.modules.event.useCases.UpdateEventUseCase;
import jakarta.validation.Valid;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/event")
public class EventController {

  @Autowired
  private CreateEventUseCase createEventUseCase;

  @Autowired
  private GetEventsUseCase getEventsUseCase;

  @Autowired
  private RemoveEventUseCase removeEventUseCase;

  @Autowired
  private UpdateEventUseCase updateEventUseCase;

  @CrossOrigin(origins = "*")
  @PostMapping("/")
  public ResponseEntity<Object> create(@Valid @RequestBody EventEntity eventEntity) {
    try {
      var result = this.createEventUseCase.execute(eventEntity);
      return ResponseEntity.ok().body(result);

    } catch (Exception e) {
      return ResponseEntity.badRequest().body(e.getMessage());
    }
  }

  @GetMapping("/list")
  public ResponseEntity<Object> getUserEvents(
      @RequestParam(name = "userId") UUID userId,
      @RequestParam(name = "startDateTime", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
      @RequestParam(name = "endDateTime", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {

    try {
      List<EventEntity> events = getEventsUseCase.execute(userId, startDate, endDate);
      return ResponseEntity.ok().body(events);

    } catch (Exception e) {
      return ResponseEntity.badRequest().body(e.getMessage());
    }
  }

  @DeleteMapping("/{eventId}")
  public ResponseEntity<Object> removeEvent(
      @PathVariable("eventId") UUID eventId,
      @RequestParam(name = "userId") UUID userId) {

    try {
      removeEventUseCase.execute(userId, eventId);
      return ResponseEntity.ok().build();
    } catch (EventNotFoundException e) {
      return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Evento não encontrado.");
    }
  }

  @PutMapping("/{eventId}")
  public ResponseEntity<Object> updateEvent(
      @PathVariable("eventId") UUID eventId,
      @RequestBody UpdateEventDTO updateEventDTO) {

    try {
      EventEntity updatedEvent = updateEventUseCase.execute(
          updateEventDTO.getUserId(),
          eventId,
          updateEventDTO.getStartDateTime(),
          updateEventDTO.getEndDateTime(),
          updateEventDTO.getDescription());

      return ResponseEntity.ok().body(updatedEvent);
    } catch (EventNotFoundException e) {
      return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Evento não encontrado.");
    }
  }
}
