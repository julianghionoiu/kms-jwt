package ro.ghionoiu.kmsjwt.token;

import io.jsonwebtoken.*;
import ro.ghionoiu.kmsjwt.key.KeyDecrypt;

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

    private static final class DecryptSigningKeyUsingKID  extends SigningKeyResolverAdapter {
        private KeyDecrypt keyDecrypt;

        DecryptSigningKeyUsingKID(KeyDecrypt keyDecrypt) {
            this.keyDecrypt = keyDecrypt;
        }

        @Override
        public Key resolveSigningKey(JwsHeader header, Claims claims) {
            String keyId = header.getKeyId();
            if (keyId == null) {
                throw new IllegalArgumentException("No key ID has been found in the JWT header");
            }
            String base64Key = keyDecrypt.decrypt(keyId);
            byte[] key = DatatypeConverter.parseBase64Binary(base64Key);
            return new SecretKeySpec(key, SignatureAlgorithm.HS256.getJcaName());
        }
    }
}
