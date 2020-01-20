package kr.jclab.iaik.pkcs11.provider.signature;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import kr.jclab.iaik.pkcs11.provider.JsIaikPkcs11Provider;
import kr.jclab.iaik.pkcs11.provider.SingletoneBouncyCastle;
import kr.jclab.iaik.pkcs11.provider.objectwrapper.WrappedPrivateKey;
import kr.jclab.iaik.pkcs11.provider.objectwrapper.WrappedPublicKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jcajce.provider.util.DigestFactory;

import java.io.IOException;
import java.security.*;

public class SignatureSpiImpl extends SignatureSpi {
    private static final int MODE_VERIFY = 1;
    private static final int MODE_SIGN = 2;

    private final Session session;
    private final String algorithm;
    private final String digestAlgorithm;
    private final Long signatureMechanism;
    private final long mechanism;

    private int mode = 0;
    private boolean useDigestFallback = false;
    private SignatureVerifyDelegate verifyDelegate = null;
    private MessageDigest fallbackDigest = null;

    public SignatureSpiImpl(JsIaikPkcs11Provider provider, String algorithm, String digestAlgorithm, Long signatureMechanism, long mechanism) {
        this.algorithm = algorithm;
        this.digestAlgorithm = digestAlgorithm;
        this.signatureMechanism = signatureMechanism;
        this.mechanism = mechanism;
        this.session = provider.getSession();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        TokenException firstException = null;
        this.mode = MODE_VERIFY;
        for(int i=0; i < 2; i++) {
            try {
                if(i == 0) {
                    if (publicKey instanceof WrappedPublicKey) {
                        this.verifyDelegate = new SignatureVerifyWithTokenDelegate(this.session, this.mechanism, (WrappedPublicKey) publicKey);
                    } else {
                        this.verifyDelegate = new SignatureVerifyWithJcaDelegate(this.algorithm, publicKey);
                    }
                    break;
                }else{
                    WrappedPublicKey wrappedPublicKey = (WrappedPublicKey)publicKey;
                    this.useDigestFallback = true;
                    this.fallbackDigest = MessageDigest.getInstance(this.digestAlgorithm, SingletoneBouncyCastle.getInstance());
                    this.session.verifyInit(Mechanism.get(this.signatureMechanism), wrappedPublicKey.getP11PublicKey());
                }
            } catch (TokenException e) {
                if (i == 0) {
                    if(checkInvalidMechanism(e)) {
                        firstException = e;
                        continue;
                    }
                } else {
                    throw new InvalidKeyException(firstException);
                }

                throw new InvalidKeyException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidKeyException(e);
            }
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if(!(privateKey instanceof WrappedPrivateKey)) {
            throw new InvalidKeyException("Must use WrappedPrivateKey");
        }
        TokenException firstException = null;
        WrappedPrivateKey wrappedPrivateKey = (WrappedPrivateKey) privateKey;
        this.mode = MODE_SIGN;
        for(int i=0; i < 2; i++) {
            try {
                if(i == 0) {
                    this.session.signInit(Mechanism.get(this.mechanism), wrappedPrivateKey.getP11PrivateKey());
                    break;
                }else{
                    this.useDigestFallback = true;
                    this.fallbackDigest = MessageDigest.getInstance(this.digestAlgorithm, SingletoneBouncyCastle.getInstance());
                    this.session.signInit(Mechanism.get(this.signatureMechanism), wrappedPrivateKey.getP11PrivateKey());
                }
            } catch (TokenException e) {
                if(i == 0) {
                    if(checkInvalidMechanism(e)) {
                        firstException = e;
                        continue;
                    }
                }else{
                    throw new InvalidKeyException(firstException);
                }
                throw new InvalidKeyException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidKeyException(e);
            }
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        byte[] buf = new byte[] { b };
        this.engineUpdate(buf, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if(this.useDigestFallback) {
            this.fallbackDigest.update(b, off, len);
            return ;
        }
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
            if(this.useDigestFallback) {
                byte[] digest = this.fallbackDigest.digest();
                return this.session.sign(createDigestInfo(digest));
            }
            return this.session.signFinal(0);
        } catch (TokenException | IOException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            if(this.useDigestFallback) {
                byte[] digest = this.fallbackDigest.digest();
                this.session.verify(createDigestInfo(digest), sigBytes);
                return true;
            }
            return this.verifyDelegate.verify(sigBytes);
        } catch (TokenException e) {
            if(this.useDigestFallback) {
                if (e instanceof PKCS11Exception) {
                    PKCS11Exception p11Exception = (PKCS11Exception) e;
                    if (p11Exception.getErrorCode() == PKCS11Constants.CKR_SIGNATURE_INVALID) {
                        return false;
                    }
                }
            }
            throw new SignatureException(e);
        } catch (IOException e) {
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

    private boolean checkInvalidMechanism(TokenException e) {
        if (e instanceof PKCS11Exception) {
            PKCS11Exception pkcs11Exception = (PKCS11Exception) e;
            return (pkcs11Exception.getErrorCode() == PKCS11Constants.CKR_MECHANISM_INVALID);
        }
        return false;
    }

    private byte[] createDigestInfo(byte[] digest) throws IOException {
        ASN1ObjectIdentifier oid = DigestFactory.getOID(this.digestAlgorithm);
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(oid);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, digest);
        return digestInfo.getEncoded();
    }

    private abstract class SignatureVerifyDelegate {
        public abstract void update(byte[] b, int offset, int length) throws TokenException, SignatureException;
        public abstract boolean verify(byte[] sig) throws SignatureException, TokenException;
    }

    private class SignatureVerifyWithTokenDelegate extends SignatureVerifyDelegate {
        private final Session session;

        SignatureVerifyWithTokenDelegate(Session session, long mechanism, WrappedPublicKey publicKey) throws TokenException {
            this.session = session;
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
