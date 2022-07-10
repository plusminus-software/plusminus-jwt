package software.plusminus.jwt.service;

import software.plusminus.security.Security;

@FunctionalInterface
public interface JwtGenerator {

    String generateAccessToken(Security security);

}
