package ro.ghionoiu.kmsjwt;

import io.jsonwebtoken.Claims;
import org.junit.Test;
import ro.ghionoiu.kmsjwt.key.DummyKeyObfuscation;
import ro.ghionoiu.kmsjwt.token.JWTDecoder;
import ro.ghionoiu.kmsjwt.token.JWTEncoder;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

/**
 * NOTE: Use https://jwt.io/ to obtain test tokens
 */
public class JWTEncoderTest {
    private static final DummyKeyObfuscation DUMMY_KEY_OBFUSCATION = new DummyKeyObfuscation();

    @Test
    public void encode_and_decode_work_together() throws Exception {
        String jwt = JWTEncoder.builder(DUMMY_KEY_OBFUSCATION)
                .claim("usr", "friendly_name")
                .compact();

        Claims claims = new JWTDecoder(DUMMY_KEY_OBFUSCATION).decodeAndVerify(jwt);

        assertThat(claims.get("usr"), is("friendly_name"));
    }
}
