package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;

public class WrappedDSAPrivateKey extends WrappedPrivateKey implements DSAPrivateKey {
    private final iaik.pkcs.pkcs11.objects.DSAPrivateKey p11PrivateKey;
    private final DSAParams params;

    public WrappedDSAPrivateKey(iaik.pkcs.pkcs11.objects.DSAPrivateKey p11PrivateKey) {
        super();
        this.p11PrivateKey = p11PrivateKey;
        this.params = WrappedDSAParams.fromByteArray(
                p11PrivateKey.getPrime().getByteArrayValue(),
                p11PrivateKey.getSubprime().getByteArrayValue(),
                p11PrivateKey.getBase().getByteArrayValue()
        );
    }

    @Override
    public iaik.pkcs.pkcs11.objects.PrivateKey getP11PrivateKey() {
        return this.p11PrivateKey;
    }

    @Override
    public BigInteger getX() {
        return null;
    }

    @Override
    public DSAParams getParams() {
        return this.params;
    }
}
