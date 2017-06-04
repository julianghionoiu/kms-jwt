package ro.ghionoiu.kmsjwt.token;

import io.jsonwebtoken.Claims;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import ro.ghionoiu.kmsjwt.key.DummyKeyProtection;
import ro.ghionoiu.kmsjwt.key.KeyDecrypt;
import ro.ghionoiu.kmsjwt.key.KeyOperationException;

import static net.trajano.commons.testing.UtilityClassTestUtil.assertUtilityClassWellDefined;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

/**
 * NOTE: Use https://jwt.io/ to obtain test tokens
 */
public class JWTEncodeDecodeTest {
    private static final byte[] SECRET_AS_BYTE_ARRAY = "secret".getBytes();
    private static final DummyKeyProtection DUMMY_KEY_PROTECTION = new DummyKeyProtection();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private JWTDecoder jwtDecoder;

    @Before
    public void setUp() throws Exception {
        jwtDecoder = new JWTDecoder(DUMMY_KEY_PROTECTION);
    }

    @Test
    public void encode_and_decode_work_together() throws Exception {
        String jwt = JWTEncoder.builder(DUMMY_KEY_PROTECTION)
                .claim("usr", "friendly_name")
                .compact();

        Claims claims = new JWTDecoder(DUMMY_KEY_PROTECTION).decodeAndVerify(jwt);

        assertThat(claims.get("usr"), is("friendly_name"));
    }

    @Test
    public void encode_is_exposed_as_utility_class() throws Exception {
        assertUtilityClassWellDefined(JWTEncoder.class);
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
    public void decode_rejects_if_key_cannot_be_decoded() throws Exception {
        String validTokenWithoutKeyId = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImMyVmpjbVYwIn0" +
                ".eyJ1c3IiOiJmcmllbmRseV9uYW1lIn0" +
                ".yQtAC9LG7qKcJi4AEzE9vOTHnMCu1eRUc3-GSx3bFC0";
        KeyDecrypt keyDecrypt = mock(KeyDecrypt.class);
        when(keyDecrypt.decrypt(any())).thenThrow(new KeyOperationException("X"));
        jwtDecoder = new JWTDecoder(keyDecrypt);
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage(containsString("Key decryption failed"));
        jwtDecoder.decodeAndVerify(validTokenWithoutKeyId);
    }

    @Test
    public void decode_uses_key_id_to_obtain_key() throws Exception {
        String validTokenWithBase64KeyIdSecret = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImMyVmpjbVYwIn0" +
                ".eyJ1c3IiOiJmcmllbmRseV9uYW1lIn0" +
                ".yQtAC9LG7qKcJi4AEzE9vOTHnMCu1eRUc3-GSx3bFC0";
        KeyDecrypt keyDecrypt = mock(KeyDecrypt.class);
        when(keyDecrypt.decrypt(any())).thenReturn(SECRET_AS_BYTE_ARRAY);
        jwtDecoder = new JWTDecoder(keyDecrypt);
        try {
            jwtDecoder.decodeAndVerify(validTokenWithBase64KeyIdSecret);
        } catch (JWTVerificationException ignored) {}

        verify(keyDecrypt).decrypt(SECRET_AS_BYTE_ARRAY);
    }

    @Test
    public void decode_rejects_if_expiration_date_in_the_past() throws Exception {
        String validKeySignedBySecretWithDateInThePast = "eyJhbGciOiJIUzI1NiIsImtpZCI6InNlY3JldCJ9" +
                ".eyJleHAiOjAsInVzciI6ImZyaWVuZGx5X25hbWUifQ" +
                ".TVMUgXwR6tO6nRD4GJ6QuC-J8tN2YOgG9ZYBYvhFgqo";
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage(containsString("expired"));
        jwtDecoder = new JWTDecoder(ciphertext -> SECRET_AS_BYTE_ARRAY);
        jwtDecoder.decodeAndVerify(validKeySignedBySecretWithDateInThePast);
    }

    @Test
    public void decode_rejects_if_keys_do_not_match() throws Exception {
        String validKeySignedBySecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ" +
                ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9" +
                ".H3y_Ox7f_ttzfDqOHQn3VeTXgllWRSKcEgZ6n7PSBeY";
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage(containsString("should not be trusted"));
        jwtDecoder = new JWTDecoder(ciphertext -> "badkey".getBytes());
        jwtDecoder.decodeAndVerify(validKeySignedBySecret);
    }

    @Test
    public void decode_accepts_valid_key() throws Exception {
        String validKeySignedBySecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ" +
                ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9" +
                ".H3y_Ox7f_ttzfDqOHQn3VeTXgllWRSKcEgZ6n7PSBeY";
        jwtDecoder = new JWTDecoder(ciphertext -> SECRET_AS_BYTE_ARRAY);
        jwtDecoder.decodeAndVerify(validKeySignedBySecret);
    }

}
