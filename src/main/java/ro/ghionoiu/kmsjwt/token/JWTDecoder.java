package ro.ghionoiu.kmsjwt.token;

import io.jsonwebtoken.*;
import ro.ghionoiu.kmsjwt.key.KeyDecrypt;
import ro.ghionoiu.kmsjwt.key.KeyOperationException;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;

public class JWTDecoder {
    private final JwtParser jwtParser;

    public JWTDecoder(KeyDecrypt keyDecrypt) {
        jwtParser = Jwts.parser()
                .setSigningKeyResolver(new DecryptSigningKeyUsingKID(keyDecrypt))
                .setAllowedClockSkewSeconds(60);
    }

    public Claims decodeAndVerify(String jwt) throws JWTVerificationException {
        try {
            return jwtParser
                    .parseClaimsJws(jwt)
                    .getBody();
        } catch (Exception e) {
            throw new JWTVerificationException(e.getMessage(), e);
        }

    }

    private static final class DecryptSigningKeyUsingKID extends SigningKeyResolverAdapter {
        private KeyDecrypt keyDecrypt;

        DecryptSigningKeyUsingKID(KeyDecrypt keyDecrypt) {
            this.keyDecrypt = keyDecrypt;
        }

        @Override
        public Key resolveSigningKey(JwsHeader header, Claims claims) {
            String keyIdBase64 = header.getKeyId();
            if (keyIdBase64 == null) {
                throw new IllegalArgumentException("No key ID has been found in the JWT header");
            }

            byte[] key;
            try {
                key = keyDecrypt.decrypt(DatatypeConverter.parseBase64Binary(keyIdBase64));
            } catch (KeyOperationException e) {
                throw new IllegalArgumentException("Key decryption failed");
            }

            return new SecretKeySpec(key, SignatureAlgorithm.HS256.getJcaName());
        }
    }
}
