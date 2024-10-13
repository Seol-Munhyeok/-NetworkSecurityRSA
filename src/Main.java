import communication.Client;
import encryption.RSAUtil;

import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    public static void main(String[] args){
        // 1. RSA 암호방식을 사용하여 암호화 하고 복호화, 사인하고 확인하는 프로그램
        try {
            KeyPair keyPair = RSAUtil.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            byte[] plainText = "Oops, I got 99 problems singing bye, bye, bye".getBytes();

            // 암호화 및 결과 출력
            byte[] cipherText = RSAUtil.encrypt(plainText, publicKey);
            System.out.println("ciphertext: " + Base64.getEncoder().encodeToString(cipherText));
            // 복호화 및 결과 출력
            byte[] decryptedText = RSAUtil.decrypt(cipherText, privateKey);
            System.out.println("decrypted: " + new String(decryptedText));
            // 서명 및 결과 출력
            byte[] signature = RSAUtil.sign(plainText, privateKey);
            System.out.println("signature: " + Base64.getEncoder().encodeToString(signature));
            // 검증 및 결과 출력
            boolean isVerified = RSAUtil.verify(plainText, signature, publicKey);
            System.out.println("isVerified: " + isVerified);

            // 2. 공개키 암호를 활용하여 문자열 전송에 비밀성을 보장하는 프로그램
            Client client = new Client("127.0.0.1", 54321);
            System.out.print("전송할 메시지를 입력하세요: ");
            Scanner scanner = new Scanner(System.in);
            String message = scanner.nextLine();
            client.sendMessage(message);
            client.close();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}