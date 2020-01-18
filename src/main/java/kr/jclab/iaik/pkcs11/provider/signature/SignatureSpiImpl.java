package kr.jclab.iaik.pkcs11.provider.signature;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import kr.jclab.iaik.pkcs11.provider.JsIaikPkcs11Provider;
import kr.jclab.iaik.pkcs11.provider.objectwrapper.WrappedPrivateKey;
import kr.jclab.iaik.pkcs11.provider.objectwrapper.WrappedPublicKey;

import java.security.*;

public class SignatureSpiImpl extends SignatureSpi {
    private static final int MODE_VERIFY = 1;
    private static final int MODE_SIGN = 2;

    private final JsIaikPkcs11Provider provider;
    private final Session session;
    private final String algorithm;
    private final long mechanism;

    private int mode = 0;
    private SignatureVerifyDelegate verifyDelegate = null;

    public SignatureSpiImpl(JsIaikPkcs11Provider provider, String algorithm, long mechanism) {
        this.provider = provider;
        this.algorithm = algorithm;
        this.mechanism = mechanism;
        this.session = provider.getSession();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        try {
            this.mode = MODE_VERIFY;
            if(publicKey instanceof WrappedPublicKey) {
                this.verifyDelegate = new SignatureVerifyWithTokenDelegate(this.session, this.mechanism, (WrappedPublicKey)publicKey);
            }else{
                this.verifyDelegate = new SignatureVerifyWithJcaDelegate(this.algorithm, publicKey);
            }
        } catch (TokenException e) {
            throw new InvalidKeyException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if(!(privateKey instanceof WrappedPrivateKey)) {
            throw new InvalidKeyException("Must use WrappedPrivateKey");
        }
        try {
            WrappedPrivateKey wrappedPrivateKey = (WrappedPrivateKey)privateKey;
            this.mode = MODE_SIGN;
            this.session.signInit(Mechanism.get(this.mechanism), wrappedPrivateKey.getP11PrivateKey());
        } catch (TokenException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        byte[] buf = new byte[] { b };
        engineUpdate(buf, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        try {
            if(this.mode == MODE_VERIFY) {
                this.verifyDelegate.update(b, 0, len);
            }else if(this.mode == MODE_SIGN) {
                this.session.signUpdate(b, 0, len);
            }else{
                throw new SignatureException(new IllegalStateException());
            }
        } catch (TokenException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            return this.session.signFinal(0);
        } catch (TokenException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            return this.verifyDelegate.verify(sigBytes);
        } catch (TokenException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    private abstract class SignatureVerifyDelegate {
        public abstract void update(byte[] b, int offset, int length) throws TokenException, SignatureException;
        public abstract boolean verify(byte[] sig) throws SignatureException, TokenException;
    }

    private class SignatureVerifyWithTokenDelegate extends SignatureVerifyDelegate {
        private final Session session;
        private final WrappedPublicKey publicKey;

        SignatureVerifyWithTokenDelegate(Session session, long mechanism, WrappedPublicKey publicKey) throws TokenException {
            this.session = session;
            this.publicKey = publicKey;
            this.session.verifyInit(Mechanism.get(mechanism), publicKey.getP11PublicKey());
        }

        @Override
        public void update(byte[] b, int offset, int length) throws TokenException {
            this.session.verifyUpdate(b, offset, length);
        }

        @Override
        public boolean verify(byte[] sig) throws TokenException {
            try {
                this.session.verifyFinal(sig);
                return true;
            }catch(TokenException e){
                if(e instanceof PKCS11Exception) {
                    PKCS11Exception p11Exception = (PKCS11Exception)e;
                    if(p11Exception.getErrorCode() == PKCS11Constants.CKR_SIGNATURE_INVALID) {
                        return false;
                    }
                }
                throw e;
            }
        }
    }

    private class SignatureVerifyWithJcaDelegate extends SignatureVerifyDelegate {
        private final Signature jcaSignature;

        SignatureVerifyWithJcaDelegate(String algorithm, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException {
            this.jcaSignature = Signature.getInstance(algorithm);
            this.jcaSignature.initVerify(publicKey);
        }

        @Override
        public void update(byte[] b, int offset, int length) throws SignatureException {
            this.jcaSignature.update(b, offset, length);
        }

        @Override
        public boolean verify(byte[] sig) throws SignatureException {
            return this.jcaSignature.verify(sig);
        }
    }
}
