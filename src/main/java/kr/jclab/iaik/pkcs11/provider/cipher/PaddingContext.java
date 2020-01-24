package kr.jclab.iaik.pkcs11.provider.cipher;

public interface PaddingContext {
    byte[] doUpdate(byte[] buffer, int offset, int length);
    byte[] doFinal();
}
