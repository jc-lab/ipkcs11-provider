package kr.jclab.iaik.pkcs11.provider.objectwrapper;

import kr.jclab.iaik.pkcs11.provider.util.Pkcs11KeyUtils;

import java.security.PublicKey;

public class WrappedPublicKey implements PublicKey {
    private final iaik.pkcs.pkcs11.objects.PublicKey p11PublicKey;

    protected WrappedPublicKey() {
        this.p11PublicKey = null;
    }

    public WrappedPublicKey(iaik.pkcs.pkcs11.objects.PublicKey p11PublicKey) {
        if(p11PublicKey == null)
            throw new NullPointerException();
        this.p11PublicKey = p11PublicKey;
    }

    public static WrappedPublicKey from(iaik.pkcs.pkcs11.objects.PublicKey p11PublicKey) {
        if(p11PublicKey instanceof iaik.pkcs.pkcs11.objects.RSAPublicKey) {
            return new WrappedRSAPublicKey((iaik.pkcs.pkcs11.objects.RSAPublicKey)p11PublicKey);
        }else if(p11PublicKey instanceof iaik.pkcs.pkcs11.objects.DSAPublicKey) {
            return new WrappedDSAPublicKey((iaik.pkcs.pkcs11.objects.DSAPublicKey)p11PublicKey);
        }else if(p11PublicKey instanceof iaik.pkcs.pkcs11.objects.ECPublicKey) {
            return new WrappedECPublicKey((iaik.pkcs.pkcs11.objects.ECPublicKey)p11PublicKey);
        }else{
            return new WrappedPublicKey(p11PublicKey);
        }
    }

    public iaik.pkcs.pkcs11.objects.PublicKey getP11PublicKey() {
        return p11PublicKey;
    }

    @Override
    public String getAlgorithm() {
        return Pkcs11KeyUtils.getAlgorithm(this.getP11PublicKey());
    }

    @Override
    public String getFormat() {
        return "PKCS11";
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}
