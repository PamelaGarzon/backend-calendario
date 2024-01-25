package br.com.pamela.calendario.modules.user.useCases;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.pamela.calendario.exceptions.UserFoundException;
import br.com.pamela.calendario.modules.user.entities.UserEntity;
import br.com.pamela.calendario.modules.user.repositories.UserRepository;

@Service
public class CreateUserUsecase {
  @Autowired
  private UserRepository userRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  public UserEntity execute(UserEntity userEntity) {
    this.userRepository
        .findByEmail(userEntity.getEmail())
        .ifPresent(user -> {
          throw new UserFoundException();
        });

    var password = passwordEncoder.encode(userEntity.getPassword());
    userEntity.setPassword(password);

    return this.userRepository.save(userEntity);

  }

}
