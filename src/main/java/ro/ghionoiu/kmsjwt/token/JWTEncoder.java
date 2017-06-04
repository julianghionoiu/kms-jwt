package ro.ghionoiu.kmsjwt.token;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import ro.ghionoiu.kmsjwt.key.KeyEncrypt;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class JWTEncoder {

    public static JwtBuilder builder(KeyEncrypt keyEncrypt) {
        SecretKey secretKey = MacProvider.generateKey(SignatureAlgorithm.HS256);
        String base64key = DatatypeConverter.printBase64Binary(secretKey.getEncoded());
        String encryptedKey = keyEncrypt.encrypt(base64key);

        return Jwts.builder()
                .setHeaderParam("kid", encryptedKey)
                .signWith(SignatureAlgorithm.HS256, secretKey);
    }

}
