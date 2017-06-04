package ro.ghionoiu.kmsjwt.key;

public class DummyKeyObfuscation implements KeyDecrypt, KeyEncrypt {
    @Override
    public String encrypt(String plaintext) {
        return "X" + plaintext + "X";
    }

    @Override
    public String decrypt(String ciphertext) {
        return ciphertext.substring(1, ciphertext.length() - 1);
    }
}
