package ro.ghionoiu.kmsjwt;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import ro.ghionoiu.kmsjwt.key.DummyKeyObfuscation;
import ro.ghionoiu.kmsjwt.key.KeyDecrypt;
import ro.ghionoiu.kmsjwt.token.JWTDecoder;
import ro.ghionoiu.kmsjwt.token.JWTVerificationException;

import javax.xml.bind.DatatypeConverter;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

/**
 * NOTE: Use https://jwt.io/ to obtain test tokens
 */
public class JWTDecoderTest {
    private static final String SECRET_AS_BASE_64 = DatatypeConverter.printBase64Binary("secret".getBytes());
    private static final DummyKeyObfuscation DUMMY_KEY_OBFUSCATION = new DummyKeyObfuscation();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private JWTDecoder jwtDecoder;

    @Before
    public void setUp() throws Exception {
        jwtDecoder = new JWTDecoder(DUMMY_KEY_OBFUSCATION);
    }

    @Test
    public void decode_rejects_empty_jwt() throws Exception {
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage(containsString("empty"));
        jwtDecoder.decodeAndVerify("");
    }

    @Test
    public void decode_rejects_invalid_jwt() throws Exception {
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage(containsString("Unable to read"));
        jwtDecoder.decodeAndVerify("X.Y.X");
    }

    @Test
    public void decode_rejects_valid_token_without_key_id() throws Exception {
        String validTokenWithoutKeyId = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                +".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"
                +".TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage(containsString("No key ID"));
        jwtDecoder.decodeAndVerify(validTokenWithoutKeyId);
    }

    @Test
    public void decode_uses_key_id_to_obtain_key() throws Exception {
        String validTokenWithKeyIdSecret = "eyJhbGciOiJIUzI1NiIsImtpZCI6InNlY3JldCJ9" +
                ".eyJ1c3IiOiJmcmllbmRseV9uYW1lIn0" +
                ".hYIZhTULU3uiufdM9KJ8vCTVIviuKaMnsfPvo7b_QLE";
        KeyDecrypt keyDecrypt = mock(KeyDecrypt.class);
        when(keyDecrypt.decrypt(anyString())).thenReturn(SECRET_AS_BASE_64);
        jwtDecoder = new JWTDecoder(keyDecrypt);
        try {
            jwtDecoder.decodeAndVerify(validTokenWithKeyIdSecret);
        } catch (JWTVerificationException ignored) {}

        verify(keyDecrypt).decrypt("secret");
    }

    @Test
    public void decode_rejects_if_expiration_date_in_the_past() throws Exception {
        String validKeySignedBySecretWithDateInThePast = "eyJhbGciOiJIUzI1NiIsImtpZCI6InNlY3JldCJ9" +
                ".eyJleHAiOjAsInVzciI6ImZyaWVuZGx5X25hbWUifQ" +
                ".TVMUgXwR6tO6nRD4GJ6QuC-J8tN2YOgG9ZYBYvhFgqo";
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage(containsString("expired"));
        jwtDecoder = new JWTDecoder(ciphertext -> SECRET_AS_BASE_64);
        jwtDecoder.decodeAndVerify(validKeySignedBySecretWithDateInThePast);
    }

    @Test
    public void decode_rejects_if_keys_do_not_match() throws Exception {
        String validKeySignedBySecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ" +
                ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9" +
                ".H3y_Ox7f_ttzfDqOHQn3VeTXgllWRSKcEgZ6n7PSBeY";
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage(containsString("should not be trusted"));
        jwtDecoder = new JWTDecoder(ciphertext -> "badkey");
        jwtDecoder.decodeAndVerify(validKeySignedBySecret);
    }

    @Test
    public void decode_accepts_valid_key() throws Exception {
        String validKeySignedBySecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ" +
                ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9" +
                ".H3y_Ox7f_ttzfDqOHQn3VeTXgllWRSKcEgZ6n7PSBeY";
        jwtDecoder = new JWTDecoder(ciphertext -> SECRET_AS_BASE_64);
        jwtDecoder.decodeAndVerify(validKeySignedBySecret);
    }

}
