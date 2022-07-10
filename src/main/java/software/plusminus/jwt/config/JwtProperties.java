package software.plusminus.jwt.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

@Data
@Configuration
@ConfigurationProperties("security.jwt")
public class JwtProperties {
    
    private Resource privateKey;
    private Resource publicKey;
    
}
