package software.plusminus.jwt.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import software.plusminus.authentication.AuthenticationParameters;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest
public class JwtIntegrationTest {

    @Autowired
    private JwtGenerator generator;
    @Autowired
    private JwtParser parser;

    @Test
    public void generator_GeneratesParseableToken() {
        //given
        AuthenticationParameters user = AuthenticationParameters.builder()
                .username("some_username")
                .roles(Stream.of("role1", "role2")
                        .collect(Collectors.toSet()))
                .build();
        //when
        String token = generator.generateAccessToken(user);
        AuthenticationParameters parsed = parser.parseToken(token);
        //then
        assertThat(parsed).isNotNull();
        assertThat(parsed.getUsername()).isEqualTo("some_username");
        assertThat(parsed.getRoles()).isEqualTo(Stream.of("role1", "role2")
                .collect(Collectors.toSet()));
    }
}
