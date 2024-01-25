package br.com.pamela.calendario;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;

import io.swagger.v3.oas.annotations.info.Info;

@SpringBootApplication
@OpenAPIDefinition(info = @Info(title = "Calendario", description = "API responsavel por criar eventos"))
public class CalendarioApplication {

	public static void main(String[] args) {
		SpringApplication.run(CalendarioApplication.class, args);
	}

}
