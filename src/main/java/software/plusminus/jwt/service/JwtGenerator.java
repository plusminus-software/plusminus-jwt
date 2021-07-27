package software.plusminus.jwt.service;

import software.plusminus.authentication.AuthenticationParameters;

@FunctionalInterface
public interface JwtGenerator {

    String generateAccessToken(AuthenticationParameters parameters);

}
