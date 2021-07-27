package software.plusminus.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;

import java.net.MalformedURLException;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

@Service
public class HttpIssuerService implements IssuerService {
    
    @Autowired
    private HttpServletRequest request;

    @Nullable
    @Override
    public String currentIssuer() {
        if (RequestContextHolder.getRequestAttributes() == null) {
            return null;
        }
        URL url;
        try {
            url = new URL(request.getRequestURL().toString());
        } catch (MalformedURLException e) {
            throw new SecurityException(e);
        }
        return url.getHost();
    }
}
