package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECPointUtil;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

public class WrappedECPublicKey extends WrappedPublicKey implements ECPublicKey {
    private final iaik.pkcs.pkcs11.objects.ECPublicKey p11PublicKey;
    private final ECParameterSpec parameterSpec;
    private final ECPoint w;

    public WrappedECPublicKey(iaik.pkcs.pkcs11.objects.ECPublicKey p11PublicKey) {
        super();
        this.p11PublicKey = p11PublicKey;
        X9ECParameters x9Params = ECParameterUtils.decodeParameterSpec(p11PublicKey.getEcdsaParams().getByteArrayValue());
        byte[] encodedPoint = p11PublicKey.getEcPoint().getByteArrayValue();
        this.parameterSpec = EC5Util.convertToSpec(x9Params);

        RuntimeException firstException = null;
        ECPoint ecPoint;
        try {
            ecPoint = EC5Util.convertPoint(x9Params.getCurve().decodePoint(encodedPoint));
        }catch (Exception e) {
            firstException = new RuntimeException(e);
            try {
                int expectedLength = (x9Params.getCurve().getFieldSize() + 7) / 8;
                if (encodedPoint[0] == 0x04) {
                    int neededLength = expectedLength * 2 + 1;
                    if (encodedPoint.length > neededLength) {
                        encodedPoint = Arrays.copyOfRange(encodedPoint, encodedPoint.length - neededLength, encodedPoint.length);
                    }
                }
                ecPoint = EC5Util.convertPoint(x9Params.getCurve().decodePoint(encodedPoint));
            }catch(Exception secondException){
                throw firstException;
            }
        }

        this.w = ecPoint;
    }

    @Override
    public iaik.pkcs.pkcs11.objects.PublicKey getP11PublicKey() {
        return this.p11PublicKey;
    }

    @Override
    public ECPoint getW() {
        return this.w;
    }

    @Override
    public ECParameterSpec getParams() {
        return this.parameterSpec;
    }
}
