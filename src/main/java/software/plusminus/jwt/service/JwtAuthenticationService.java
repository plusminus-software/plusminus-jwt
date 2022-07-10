package software.plusminus.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import software.plusminus.authentication.model.TokenPlace;
import software.plusminus.authentication.service.Authenticator;
import software.plusminus.security.Security;

@Service
public class JwtAuthenticationService implements Authenticator {
    
    @Autowired
    private JwtGenerator generator;
    @Autowired
    private JwtParser parser;
    
    @Override
    public TokenPlace tokenPlace() {
        return TokenPlace.builder()
                .headersKey("Authorization")
                .cookiesKey("JWT-TOKEN")
                .build();
    }
    
    @Override
    public Security authenticate(String token) {
        return parser.parseToken(token);
    }
    
    @Override
    public String provideToken(Security security) {
        return generator.generateAccessToken(security);
    }
}
