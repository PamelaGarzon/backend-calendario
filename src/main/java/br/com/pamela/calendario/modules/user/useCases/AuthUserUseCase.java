package br.com.pamela.calendario.modules.user.useCases;

import java.time.Duration;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import br.com.pamela.calendario.exceptions.UserInvalidLoginException;
import br.com.pamela.calendario.modules.user.dto.AuthUserRequestDTO;
import br.com.pamela.calendario.modules.user.dto.AuthUserResponseDTO;
import br.com.pamela.calendario.modules.user.repositories.UserRepository;

@Service
public class AuthUserUseCase {

  @Value("${security.token.secret}")
  private String secretKey;

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  public AuthUserResponseDTO execute(AuthUserRequestDTO authUserRequestDTO) {
    var user = this.userRepository.findByEmail(authUserRequestDTO.getEmail())
        .orElseThrow(() -> new UserInvalidLoginException());

    var passwordMatches = (boolean) this.passwordEncoder.matches(authUserRequestDTO.getPassword(), user.getPassword());

    if (!passwordMatches) {
      throw new UserInvalidLoginException();
    }

    Algorithm algorithm = Algorithm.HMAC256(secretKey);
    var token = JWT.create()
        .withIssuer("user")
        .withExpiresAt(Instant.now().plus(Duration.ofHours(2)))
        .withSubject(user.getId().toString())
        .sign(algorithm);

    var authUserResponse = AuthUserResponseDTO.builder()
        .access_token(token)
        .expires_in(Instant.now().plus(Duration.ofHours(2)).toEpochMilli())
        .userId(user.getId().toString())
        .build();

    return authUserResponse;
  }
}