package software.plusminus.jwt.service;

import org.springframework.lang.Nullable;

public interface IssuerService {
    
    @Nullable
    String currentIssuer();
    
}
