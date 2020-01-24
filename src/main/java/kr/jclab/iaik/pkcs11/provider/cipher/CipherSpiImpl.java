package kr.jclab.iaik.pkcs11.provider.cipher;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import kr.jclab.iaik.pkcs11.provider.JsIaikPkcs11Provider;
import kr.jclab.iaik.pkcs11.provider.objectwrapper.WrappedSecretKey;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

public class CipherSpiImpl extends CipherSpi {
    private final JsIaikPkcs11Provider provider;
    private final Session session;
    private final Long mechanismCode;
    private int mode = -1;
    private final PaddingProvider paddingProvider;
    private CryptoDelegate cryptoDelegate;
    private PaddingContext paddingContext;
    private byte[] iv;
    private int blockSize;

    private static class SingletoneHolder {
        private static final Set<Long> IV_MECHANISM;

        static {
            Set<Long> ivMechanism = new HashSet<>();
            ivMechanism.add(PKCS11Constants.CKM_AES_CBC);
            ivMechanism.add(PKCS11Constants.CKM_AES_CBC_PAD);
            ivMechanism.add(PKCS11Constants.CKM_AES_CFB1);
            ivMechanism.add(PKCS11Constants.CKM_AES_CFB8);
            ivMechanism.add(PKCS11Constants.CKM_AES_CFB64);
            ivMechanism.add(PKCS11Constants.CKM_AES_CFB128);
            ivMechanism.add(PKCS11Constants.CKM_AES_OFB);
            ivMechanism.add(PKCS11Constants.CKM_AES_GCM);
            IV_MECHANISM = Collections.unmodifiableSet(ivMechanism);
        }
    }

    public CipherSpiImpl(JsIaikPkcs11Provider provider, Long mechanismCode, int fixedBlockSize, PaddingProvider paddingProvider) {
        this.provider = provider;
        this.mechanismCode = mechanismCode;
        this.session = provider.getSession();
        this.paddingProvider = paddingProvider;
        this.blockSize = fixedBlockSize;
    }

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException {

    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException {

    }

    @Override
    protected int engineGetBlockSize() {
        return this.blockSize;
    }

    @Override
    protected int engineGetOutputSize(int i) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return this.iv.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int mode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        WrappedSecretKey wrappedSecretKey = (WrappedSecretKey)key;

        this.mode = mode;

        try {
            Mechanism mechanism = Mechanism.get(this.mechanismCode);
            if(SingletoneHolder.IV_MECHANISM.contains(this.mechanismCode)) {
                if(mode == Cipher.ENCRYPT_MODE && this.iv == null) {
                    this.iv = this.session.generateRandom(this.engineGetBlockSize());
                }
                mechanism.setParameters(new InitializationVectorParameters(this.iv));
            }
            if (mode == Cipher.ENCRYPT_MODE) {
                this.session.encryptInit(mechanism, wrappedSecretKey.getP11SecretKey());
                this.cryptoDelegate = new EncryptDelegate();
            }else if (mode == Cipher.DECRYPT_MODE) {
                this.session.decryptInit(mechanism, wrappedSecretKey.getP11SecretKey());
                this.cryptoDelegate = new DecryptDelegate();
            }else{
                throw new InvalidKeyException("Not supported mode yet");
            }
            this.paddingContext = this.paddingProvider.newInstance(this.engineGetBlockSize(), mode);
        } catch (TokenException e) {
            throw new InvalidKeyException(e);
        }

    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if(algorithmParameterSpec instanceof IvParameterSpec) {
            this.iv = ((IvParameterSpec)algorithmParameterSpec).getIV();
        }else{
            throw new InvalidAlgorithmParameterException("Not supported mode yet");
        }
        engineInit(i, key, secureRandom);
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("Not supported mode yet");
    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int offset, int length) {
        byte[] outBuffer = new byte[length];
        int outLength = 0;
        try {
            outLength = this.cryptoDelegate.doUpdate(bytes, offset, length, outBuffer, 0, outBuffer.length);
        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
        return Arrays.copyOf(outBuffer, outLength);
    }

    @Override
    protected int engineUpdate(byte[] bytes, int inOffset, int inLength, byte[] outBuffer, int outSize) throws ShortBufferException {
        int outLength = 0;
        try {
            outLength = this.cryptoDelegate.doUpdate(bytes, inOffset, inLength, outBuffer, 0, outSize);
        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
        return outLength;
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int inOffset, int inLength) throws IllegalBlockSizeException, BadPaddingException {
        int outPosition = 0;
        byte[] outBuffer = new byte[inLength + this.engineGetBlockSize()];
        try {
            if(bytes != null && inLength > 0) {
                int tempLength = this.cryptoDelegate.doUpdate(bytes, inOffset, inLength, outBuffer, outPosition, outBuffer.length - outPosition);
                outPosition += tempLength;
            }
            outPosition += this.cryptoDelegate.doFinal(outBuffer, outPosition, outBuffer.length - outPosition);
        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
        return Arrays.copyOf(outBuffer, outPosition);
    }

    @Override
    protected int engineDoFinal(byte[] bytes, int inOffset, int inLength, byte[] outBuffer, int outSize) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int outLength = 0;
        int outOffset = 0;
        try {
            if(bytes != null && inLength > 0) {
                int tempLength = this.cryptoDelegate.doUpdate(bytes, inOffset, inLength, outBuffer, outOffset, outLength - outOffset);
                outOffset += tempLength;
                outLength += tempLength;
            }
            outLength += this.cryptoDelegate.doFinal(outBuffer, outOffset, outSize - outOffset);
        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
        return outLength;
    }

    public abstract class CryptoDelegate {
        public abstract int doUpdate(byte[] input, int inOffset, int inLength, byte[] output, int outOffset, int outLength) throws TokenException;
        public abstract int doFinal(byte[] output, int outOffset, int outLength) throws TokenException;
    }

    public class EncryptDelegate extends CryptoDelegate {
        @Override
        public int doUpdate(byte[] input, int inOffset, int inLength, byte[] output, int outOffset, int outLength) throws TokenException {
            byte[] temp = paddingContext.doUpdate(input, inOffset, inLength);
            return session.encryptUpdate(temp, 0, temp.length, output, outOffset, outLength);
        }

        @Override
        public int doFinal(byte[] output, int outOffset, int outLength) throws TokenException {
            byte[] finalBlock = paddingContext.doFinal();
            int updateLen = 0;
            if(finalBlock != null && finalBlock.length > 0) {
                int temp = session.encryptUpdate(finalBlock, 0, finalBlock.length, output, outOffset, outLength);
                outOffset += temp;
                outLength -= temp;
                updateLen += temp;
            }
            updateLen += session.encryptFinal(output, outOffset, outLength);
            return updateLen;
        }
    }

    public class DecryptDelegate extends CryptoDelegate {
        @Override
        public int doUpdate(byte[] input, int inOffset, int inLength, byte[] output, int outOffset, int outLength) throws TokenException {
            int updateLen = session.decryptUpdate(input, inOffset, inLength, output, outOffset, outLength);
            byte[] temp = paddingContext.doUpdate(output, outOffset, updateLen);
            if(temp != null && temp.length > 0) {
                System.arraycopy(temp, 0, output, outOffset, temp.length);
                return temp.length;
            }
            return 0;
        }

        @Override
        public int doFinal(byte[] output, int outOffset, int outLength) throws TokenException {
            int updateLen = session.decryptFinal(output, outOffset, outLength);
            byte[] temp = paddingContext.doUpdate(output, outOffset, updateLen);
            if(temp != null && temp.length > 0) {
                System.arraycopy(temp, 0, output, outOffset, temp.length);
                outOffset -= temp.length;
                updateLen += temp.length;
            }

            temp = paddingContext.doFinal();
            System.arraycopy(temp, 0, output, outOffset, temp.length);
            updateLen += temp.length;

            return updateLen;
        }
    }
}
