import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class X509Test {

    private String pid;

    @BeforeEach
    void init() throws IOException {
        pid = UUID.randomUUID().toString();
        String rootCert = X509Test.class.getResource("/gd-class2-root.crt").getPath();
        buildTrustStore(rootCert);
        //keytool -importcert -alias gd -trustcacerts -file sonatype.pem -cacerts
    }

    @Test
    void testSonatypeCert() throws IOException {
        //Reader rootCert = new BufferedReader(new InputStreamReader(X509Test.class.getResourceAsStream("/gd-class2-root.crt")));
        Process p2 = Runtime.getRuntime().exec("keytool -printcert -rfc -sslserver oss.sonatype.org:443");
        Reader endCert = new BufferedReader(new InputStreamReader(p2.getInputStream()));
        //InputStream ks = new FileInputStream(System.getenv("JAVA_HOME") + "/lib/security/cacerts");
        InputStream ks = new FileInputStream(System.getenv("PWD") + "/lib/security/keystore-" + pid + ".jks");
        String password = "changeit";
        char[] pw = password.toCharArray();
        Reader intCert = new FileReader(X509Test.class.getResource("/gd_intermediate.crt.pem").getPath());
        //Reader intCert = new BufferedReader(new InputStreamReader(X509Test.class.getResourceAsStream("/gdig2.crt")));
        //String cert = X509Test.class.getResource("/sonatype.pem").getPath();
        List<Reader> certs = new ArrayList<>();
        //certs.add(rootCert);
        certs.add(intCert);
        certs.add(endCert);
        validateX509(certs, ks, pw);
    }

    @Test
    void testAmazonCert() {
        String cert = X509Test.class.getResource("/AmazonRootCA1.pem").getPath();
        List<Reader> certs = new ArrayList<>();
        //certs.add(cert);
        validateX509(certs, null, null);
    }

    @Test
    void testNGACert() {
        String cert = X509Test.class.getResource("/media.nga.gov").getPath();
        List<String> certs = new ArrayList<>();
        certs.add(cert);
        //validateX509(certs, null, null);
    }

    @Test
    void testStanfordCert() {
        String cert = X509Test.class.getResource("/purl.stanford.edu").getPath();
        List<String> certs = new ArrayList<>();
        certs.add(cert);
        //validateX509(certs, null, null);
    }

    private void buildTrustStore(String rootCert) throws IOException {
        String ksFileName = "keystore-" + pid + ".jks";
        String ksOutputPath = System.getenv("PWD") + "/lib/security/";
        String[] commands = {"keytool", "-storepass", "changeit", "-alias", "testCA", "-noprompt", "-keystore",
                ksFileName, "-import", "-file", rootCert};
        ProcessBuilder pb = new ProcessBuilder(commands);
        pb.directory(new File(ksOutputPath));
        Process p1 = pb.start();
        // return new BufferedInputStream(p1.getInputStream());
    }

    private void validateX509(List<Reader> certs, InputStream keystore, char[] password) {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(keystore, password);
            PKIXBuilderParameters params = new PKIXBuilderParameters(ks, new X509CertSelector());
            JcaCertStoreBuilder builder = new JcaCertStoreBuilder();
            for (Reader cert : certs) {
                PEMParser pars = new PEMParser(cert);
                Object c = pars.readObject();
                if (c instanceof X509CertificateHolder) {
                    builder.addCertificate((X509CertificateHolder) c);
                }
            }
            params.addCertStore(builder.build());
            params.setRevocationEnabled(false);
            CertPathBuilder cpBuilder = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
            PKIXCertPathBuilderResult r = (PKIXCertPathBuilderResult) cpBuilder.build(params);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Sucessfully Validated");
    }

    private static X509Certificate getCertificate(InputStream cert) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(cert);
    }

    @Test
    void testGetSystemProps() {
        Map<String, String> env = System.getenv();
        for (String envName : env.keySet()) {
            System.out.format("%s=%s%n", envName, env.get(envName));
        }
        Properties props = System.getProperties();
        props.list(System.out);
    }
}
