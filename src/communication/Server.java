package communication;

import encryption.RSAUtil;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Server {
    private final int port;

    public Server(int port) {
        this.port = port;
    }

    public void start() throws Exception {
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server started on port " + port);

        while (true) {
            Socket socket = serverSocket.accept();
            DataInputStream in  = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // RSA 키 쌍 생성
            KeyPair keyPair = RSAUtil.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 공개키를 클라이언트에 전송
            byte[] publicKeyBytes = publicKey.getEncoded();
            System.out.println("공개키를 전송합니다: " + Base64.getEncoder().encodeToString(publicKeyBytes));
            out.writeInt(publicKeyBytes.length);
            out.write(publicKeyBytes);
            out.flush();

            // 암호문을 클라이언트로부터 수신
            int length = in.readInt();
            byte[] cipherTextBytes = new byte[length];
            in.readFully(cipherTextBytes);
            System.out.println("수신한 암호화된 메시지: " + Base64.getEncoder().encodeToString(cipherTextBytes));

            // 수신한 암호문을 개인키를 사용해 복호화
            byte[] decryptedText = RSAUtil.decrypt(cipherTextBytes, privateKey);
            System.out.println("복호화된 메시지: " + new String(decryptedText));

            socket.close();
        }
    }

    public static void main(String[] args) throws Exception {
        Server server = new Server(54321);
        server.start();
    }
}
