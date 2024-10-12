import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

public class Main {
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        // RSA 키 쌍 생성
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);

        return keyGen.generateKeyPair();
    }

    public static void main(String[] args){
        try {
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            byte[] plaintext = "Hello, RSA encryption!".getBytes();
            // 암호화 및 결과 출력
            byte[] ciphertext = RSAUtil.encrypt(plaintext, publicKey);
            System.out.println("ciphertext: " + Base64.getEncoder().encodeToString(ciphertext));
            // 복호화 및 결과 출력
            byte[] decrypted = RSAUtil.decrypt(ciphertext, privateKey);
            System.out.println("decrypted: " + new String(decrypted));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}