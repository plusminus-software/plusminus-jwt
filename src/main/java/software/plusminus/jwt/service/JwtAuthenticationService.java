package software.plusminus.jwt.service;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import software.plusminus.security.Security;
import software.plusminus.security.service.TokenService;

import javax.annotation.Nullable;

@AllArgsConstructor
@Service
public class JwtAuthenticationService implements TokenService {
    
    private JwtGenerator generator;
    private JwtParser parser;

    @Nullable
    @Override
    public Security getSecurity(String token) {
        return parser.parseToken(token);
    }
    
    @Override
    public String getToken(Security security) {
        return generator.generateAccessToken(security);
    }
}
