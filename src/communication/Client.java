package communication;

import encryption.RSAUtil;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Client {
    private final Socket socket;
    private final DataInputStream in;
    private final DataOutputStream out;
    private final PublicKey publicKey;

    public Client(String serverIP, int serverPort) throws Exception {
        this.socket = new Socket(serverIP, serverPort);
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
        this.publicKey = getPublicKey();
        System.out.println("서버에 연결되었습니다.");
    }

    public PublicKey getPublicKey() throws Exception {
        int length = in.readInt();
        byte[] publicKeyBytes = new byte[length];
        in.readFully(publicKeyBytes);
        System.out.println("공개키가 수신되었습니다: " + Base64.getEncoder().encodeToString(publicKeyBytes));
        // PublicKey 객체로 변환
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

        return keyFactory.generatePublic(keySpec);
    }

    public void sendMessage(String message) throws Exception {
        byte[] messageBytes = message.getBytes();
        byte[] encryptedMessage = RSAUtil.encrypt(messageBytes, publicKey);

        out.writeInt(encryptedMessage.length);
        out.write(encryptedMessage);  // 암호화해서 전송
    }

    public void close() throws Exception {
        if (socket != null && !socket.isClosed()) {
            socket.close();
            System.out.println("서버와의 연결이 종료되었습니다.");
        }
    }
}
