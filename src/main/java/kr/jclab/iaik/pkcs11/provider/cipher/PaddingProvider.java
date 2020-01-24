package kr.jclab.iaik.pkcs11.provider.cipher;

public interface PaddingProvider {
    PaddingContext newInstance(int blockSize, int mode);
}
