package software.plusminus.jwt.service;

import software.plusminus.authentication.AuthenticationParameters;

@FunctionalInterface
public interface JwtParser {

    AuthenticationParameters parseToken(String token);

}
