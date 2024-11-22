package demo;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import net.tongsuo.TongsuoProvider;
import net.tongsuo.TongsuoX509Certificate;
import net.tongsuo.TlcpKeyManagerImpl;


public class TLCPServer {
    public static void main(String[] args)throws Exception{
        String[] ciphers = {"ECC-SM2-SM4-GCM-SM3"};
        String caCertFile = "ca.crt";
        String subCaCertFile = "subca.crt";
        String serverEncCrtFile = "server_enc.crt";
        String serverSignCrtFile = "server_sign.crt";
        String serverEncKeyFile = "server_enc.key";
        String serverSignKeyFile = "server_sign.key";

        char[] EMPTY_PASSWORD = new char[0];
        X509Certificate ca = TongsuoX509Certificate.fromX509PemInputStream(new FileInputStream(new File(caCertFile)));
        X509Certificate subCa = TongsuoX509Certificate.fromX509PemInputStream(new FileInputStream(new File(subCaCertFile)));
        PrivateKey serverSignPrivateKey = readSM2PrivateKeyPemFile(serverSignKeyFile);
        PrivateKey serverEncPrivateKey = readSM2PrivateKeyPemFile(serverEncKeyFile);
        X509Certificate serverSignCert = TongsuoX509Certificate.fromX509PemInputStream(new FileInputStream(new File(serverSignCrtFile)));
        X509Certificate serverEncCert = TongsuoX509Certificate.fromX509PemInputStream(new FileInputStream(new File(serverEncCrtFile)));

        X509Certificate[] serverSignCertChain = new X509Certificate[]{serverSignCert, subCa, ca};
        X509Certificate[] serverEncCertChain = new X509Certificate[]{serverEncCert, subCa, ca};

        Security.addProvider(new TongsuoProvider());

        KeyStore ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
        ks.load(null);
        ks.setKeyEntry("server_enc", serverEncPrivateKey, EMPTY_PASSWORD, serverEncCertChain);
        ks.setKeyEntry("server_sign", serverSignPrivateKey, EMPTY_PASSWORD, serverSignCertChain);
        ks.setCertificateEntry("CA", ca);
        ks.setCertificateEntry("SUB_CA", subCa);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("TlcpKeyManagerFactory", new TongsuoProvider());
        kmf.init(ks, EMPTY_PASSWORD);
        KeyManager serverKey = kmf.getKeyManagers()[0];
        TlcpKeyManagerImpl tlcpKeyManager = (TlcpKeyManagerImpl) serverKey;
        KeyManager[] serverKeyManager = new KeyManager[]{serverKey};
        tlcpKeyManager.setTlcpEncAlias("server_enc");
        tlcpKeyManager.setTlcpSignAlias("server_sign");

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        TrustManager[] serverTrustManager = tmf.getTrustManagers();


        SSLContext sslContext = SSLContext.getInstance("TLCP", new TongsuoProvider());
        System.out.println(sslContext.getProtocol());
        sslContext.init(serverKeyManager, serverTrustManager, new SecureRandom());

        SSLServerSocketFactory serverFactory = sslContext.getServerSocketFactory();
        SSLServerSocket svrSocket = (SSLServerSocket) serverFactory.createServerSocket(38636);
        svrSocket.setEnabledCipherSuites(ciphers);

        System.out.println("Server SSL context init success...");

        while (true){
            SSLSocket sslSocket = (SSLSocket)svrSocket.accept();

            try {
                BufferedReader ioReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), StandardCharsets.UTF_8));
                PrintWriter ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream(), StandardCharsets.UTF_8)));

                String msg = null;
                char[] cbuf = new char[1024];
                int len = 0;
                while( (len = ioReader.read(cbuf, 0, 1024)) != -1 ){ // 循环读取输入流中的内容
                    msg = new String(cbuf, 0, len);
                    ioWriter.write(msg);
                    ioWriter.flush();

                    if("Bye".equals(msg)) { // 如果检测到 "Bye" ，则跳出循环，不再读取输入流中内容。
                        break;
                    }
                    System.out.printf("Received Message --> %s \n", msg);
                }
            }catch (IOException e){
                e.printStackTrace();
            }
        }
    }

    public static PrivateKey readSM2PrivateKeyPemFile(String name)throws Exception{
        InputStreamReader inputStreamReader = new InputStreamReader(new FileInputStream(new File(name)), StandardCharsets.UTF_8);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        StringBuilder sb = new StringBuilder();
        String line = null;
            while ((line = bufferedReader.readLine()) != null){
            if(line.startsWith("-")){
                continue;
            }
            sb.append(line).append("\n");
        }
        String ecKey = sb.toString().replaceAll("\\r\\n|\\r|\\n", "");
        Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] keyByte = base64Decoder.decode(ecKey.getBytes(StandardCharsets.UTF_8));
        PKCS8EncodedKeySpec eks2 = new PKCS8EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PrivateKey privateKey = keyFactory.generatePrivate(eks2);
            return privateKey;
    }
}
