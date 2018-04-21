import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class X509Test {

    @BeforeEach
    void init() {
        //keytool -importcert -alias gd -trustcacerts -file sonatype.pem -cacerts
    }

    @Test
    void testSonatypeCert() {
        String cert = X509Test.class.getResource("/sonatype.pem").getPath();
        validateX509(cert);
    }

    @Test
    void testAmazonCert() {
        String cert = X509Test.class.getResource("/AmazonRootCA1.pem").getPath();
        validateX509(cert);
    }

    @Test
    void testNGACert() {
        String cert = X509Test.class.getResource("/media.nga.gov").getPath();
        validateX509(cert);
    }

    @Test
    void testStanfordCert() {
        String cert = X509Test.class.getResource("/purl.stanford.edu").getPath();
        validateX509(cert);
    }

    private void validateX509(String cert) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "changeit";
            char[] pw = password.toCharArray();
            ks.load(new FileInputStream("/usr/lib/jvm/jdk-10/lib/security/cacerts"), pw);
            PKIXBuilderParameters params = new PKIXBuilderParameters(ks, new X509CertSelector());
            JcaCertStoreBuilder builder = new JcaCertStoreBuilder();
            FileReader f = new FileReader(cert);
            PEMParser pars = new PEMParser(f);
            Object c = pars.readObject();
            if (c instanceof X509CertificateHolder) {
                builder.addCertificate((X509CertificateHolder) c);
            }
            params.addCertStore(builder.build());
            params.setRevocationEnabled(false);
            CertPathBuilder cpBuilder = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
            PKIXCertPathBuilderResult r = (PKIXCertPathBuilderResult) cpBuilder.build(params);
        } catch (Exception e) {
            System.out.println(e);
            System.out.println(e.getCause());
        }
    }
}
