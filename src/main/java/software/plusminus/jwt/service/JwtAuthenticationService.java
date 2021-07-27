package software.plusminus.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import software.plusminus.authentication.AuthenticationParameters;
import software.plusminus.authentication.AuthenticationService;

@Service
public class JwtAuthenticationService implements AuthenticationService {
    
    @Autowired
    private JwtGenerator generator;
    @Autowired
    private JwtParser parser;
    
    @Override
    public AuthenticationParameters parseToken(String token) {
        return parser.parseToken(token);
    }
    
    @Override
    public String generateToken(AuthenticationParameters parameters) {
        return generator.generateAccessToken(parameters);
    }
}
