package software.plusminus.jwt.service;

import software.plusminus.security.Security;

@FunctionalInterface
public interface JwtParser {

    Security parseToken(String token);

}
