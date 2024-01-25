package br.com.pamela.calendario.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity

public class SecurityConfig {

  @Autowired
  private SecurityUserFilter securityUserFilter;

  private static final String[] SWAGGER_LIST = {
      "swagger-ui/**",
      "/v3/api-doc/**",
      "/swagger-resource/**"
  };

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // desabilita pois o token já é uma proteção contra ataque
    http
        .csrf(AbstractHttpConfigurer::disable)
        .authorizeRequests(auth -> {
          auth
              .requestMatchers("/user", "/user/auth").permitAll()
              .requestMatchers(SWAGGER_LIST).permitAll();
          auth.anyRequest().authenticated();
        })
        .httpBasic(withDefaults())
        .addFilterBefore(securityUserFilter, BasicAuthenticationFilter.class);
    // security filter -> filtro de segurança
    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();

  }

}
