package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

public class WrappedECPrivateKey extends WrappedPrivateKey implements ECPrivateKey {
    private final iaik.pkcs.pkcs11.objects.ECPrivateKey p11PrivateKey;
    private final ECParameterSpec parameterSpec;

    public WrappedECPrivateKey(iaik.pkcs.pkcs11.objects.ECPrivateKey p11PrivateKey) {
        super();
        this.p11PrivateKey = p11PrivateKey;
        this.parameterSpec = EC5Util.convertToSpec(ECParameterUtils.decodeParameterSpec(p11PrivateKey.getEcdsaParams().getByteArrayValue()));
    }

    @Override
    public iaik.pkcs.pkcs11.objects.PrivateKey getP11PrivateKey() {
        return this.p11PrivateKey;
    }

    @Override
    public BigInteger getS() {
        return null;
    }

    @Override
    public ECParameterSpec getParams() {
        return this.parameterSpec;
    }
}
