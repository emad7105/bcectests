import com.sun.tools.javac.util.Assert;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.security.SecureRandom;

public class Main {

    public static void main(String[] args) throws IOException {
        // Generate keys
        String curve = "secp256k1";
        ECDomainParameters domainParams = createECDomainParams(curve);
        AsymmetricCipherKeyPair keyPair = generateKeys(domainParams);
        AsymmetricKeyParameter pk = keyPair.getPublic();
        AsymmetricKeyParameter sk = keyPair.getPrivate();

        // get encoded (keys)
        byte[] pkEncoded = getEncoded(pk);
        byte[] skEncoded = getEncoded(sk);

        // import the Public Key
        ECPublicKeyParameters importedPk = publicKeyFromBytes(pkEncoded);
        ECPoint q = importedPk.getQ();
        //q = ECAlgorithms.importPoint(domainParams.getCurve(), q);

        Assert.check(q.getCurve().equals(domainParams.getCurve()));

        // ==> IllegalArgumentException: 'points' entries must be null or on this curve
        domainParams.getCurve().normalizeAll(new ECPoint[]{q});
    }


    private static ECDomainParameters createECDomainParams(String curve) {
        X9ECParameters ecp = SECNamedCurves.getByName(curve);
        ECDomainParameters domainParams = new ECDomainParameters(
                ecp.getCurve(),
                ecp.getG(),
                ecp.getN(),
                ecp.getH(),
                ecp.getSeed());
        return domainParams;
    }


    public static AsymmetricCipherKeyPair generateKeys(ECDomainParameters domainParams) {
        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(keyGenParams);
        return generator.generateKeyPair();
    }

    public static byte[] getEncoded(AsymmetricKeyParameter key) throws IOException {
        return key.isPrivate() ?
                PrivateKeyInfoFactory.createPrivateKeyInfo(key).getEncoded() :
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key).getEncoded();
    }

    public static ECPublicKeyParameters publicKeyFromBytes(byte[] pk) throws IOException {
        return (ECPublicKeyParameters) PublicKeyFactory.createKey(pk);
    }
}
