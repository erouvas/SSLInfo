/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package gr.rouvas.sslinfo;

import java.math.BigInteger;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.cert.X509Certificate;

/**
 *
 * run with Maven:
 *
 * mvn clean install exec:java -Dexec.mainClass=gr.rouvas.sslinfo.SSLinfo
 * "-Dexec.args=www.theregister.co.uk 443" -quiet
 *
 * or outside Maven with
 *
 * java -cp SSLinfo-1.0.jar gr.rouvas.sslinfo.SSLinfo www.theregister.co.uk 443
 *
 * More info at : The correct way to do it:
 * https://developers.redhat.com/blog/2017/10/27/ssl-testing-tool/
 *
 * The accept-all workaround:
 * http://www.java2s.com/Code/Java/Network-Protocol/DisablingCertificateValidationinanHTTPSConnection.htm
 * https://stackoverflow.com/questions/7615645/ssl-handshake-alert-unrecognized-name-error-since-upgrade-to-java-1-7-0
 *
 */
public class SSLinfo {

  static String CACERTS_LOCATION = "/home/rouvas/bin/java/jre/lib/security/cacerts";

  private static final TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
      @Override
      public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
      }

      @Override
      public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
      }

      @Override
      public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        return new java.security.cert.X509Certificate[]{};}}};

  private static final SSLContext trustAllSslContext;

  static {
    try {
      trustAllSslContext = SSLContext.getInstance("SSL");
      trustAllSslContext.init(null, trustAllCerts, new java.security.SecureRandom());
    } catch (NoSuchAlgorithmException | KeyManagementException e) {
      throw new RuntimeException(e);
    }
  }

  public static void main(String[] args) {
    String hostname;
    Integer port;

    if (args.length != 2) {
      hostname = "google.com";
      port = 443;
    } else {
      hostname = args[0];
      port = Integer.valueOf(args[1]);
    }

    //
    // required after Java.7 to workaround some servers with spurious responses
    //
    // alternative for not recompiling: java -Djsse.enableSNIExtension=false
    // yourClas
    //
    System.setProperty("jsse.enableSNIExtension", "false");

    try {

      // the following lines are used to accept any and all SSL certificatess
      SSLContext sc = SSLContext.getInstance("SSL");
      sc.init(null, trustAllCerts, new java.security.SecureRandom());

      SSLSocketFactory sslSocketFactory = sc.getSocketFactory();

      SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(hostname, port);
      sslSocket.startHandshake();
      SSLSession sslSession = (SSLSession) sslSocket.getSession();

      System.out.println("SSLSession :");
      System.out.println("\tSessionID: " + new BigInteger(sslSession.getId()));
      System.out.println("\tProtocol : " + sslSession.getProtocol());
      System.out.println("\tCipher suite : " + sslSession.getCipherSuite());
      System.out.println("\tServer: " + sslSession.getPeerHost());
      System.out.println("\tSSL Port: " + sslSession.getPeerPort());

      System.out.println("\nSupported Protocol :");
      for (String enabledProtocol : sslSocket.getEnabledProtocols()) {
        System.out.println("\t" + enabledProtocol);
      }

      System.out.println("\nSupported CipherSuites: ");
      for (String enabledCipherSuite : sslSocket.getEnabledCipherSuites()) {
        System.out.println("\t" + enabledCipherSuite);
      }

      X509Certificate[] certs = (X509Certificate[]) sslSession.getPeerCertificateChain();
      System.out.println("\nCertificate Chain Info :");
      for (X509Certificate cert : certs) {
        System.out.println("\tSubject DN :" + ((X509Certificate) cert).getSubjectDN());
        System.out.println("\tIssuer DN  : " + ((X509Certificate) cert).getIssuerDN());
        System.out.println("\tSerial No. : " + ((X509Certificate) cert).getSerialNumber());
        System.out.println("\tExpires On : " + ((X509Certificate) cert).getNotAfter() + "\n");
      }
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

}
