import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.Base64;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;

public class SSLClient implements HandshakeCompletedListener {

    private Socket  socket;

    public SSLClient(String url) throws UnknownHostException, IOException{
        SocketFactory factory = SSLSocketFactory.getDefault();
        this.socket = factory.createSocket(url, 443);
    }
    // Metodos a implementar para realizar el handshake asíncrono
    /*
     * The HandshakeCompletedEvent class provides four methods for getting information about the event:
        - public SSLSession getSession()
        - public String getCipherSuite()
        - public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException
        - public SSLSocket getSocket()
     */
    @Override
    public void handshakeCompleted(HandshakeCompletedEvent event) {
        
        try {
            // CipherSuites exchanged on Handshake, these ones are the result of the handshake connection
            System.out.println("--------------------------------------------------------------");
            System.out.println("Supported Cipher Suites From Server:\n" + event.getCipherSuite());
            System.out.println("--------------------------------------------------------------\n\n");

            int i = 1 ;
            for(Certificate cert :  event.getPeerCertificates()){
                System.out.println(" Certificate[" + i++ +"] -->\n" + 
                    new String ( Base64.getEncoder().encode(cert.getEncoded()) , StandardCharsets.US_ASCII));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void startConn(){
        // CipherSuites that the client will choose during KeyExchange, this method does not 
        // connect to the server and starts the handshake. 
        // The actual suite used is negotiated between the client and server at connection time
        for (String cipherSuites : ((SSLSocket ) socket).getSupportedCipherSuites()){
            System.out.println(cipherSuites);
        }
        // Registers an event listener to receive notifications that an SSL handshake has completed on this connection.
        ((SSLSocket ) socket).addHandshakeCompletedListener(this);
        try {
            ((SSLSocket ) socket).startHandshake();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void main(String [] args){
        try{
            SSLClient newClient = new SSLClient("www.marca.com");
            newClient.startConn();
        }catch(Exception e){}
        return;
    }
    
}
