package kr.jclab.iaik.pkcs11.provider.cipher;

import java.util.Arrays;

public class NoPaddingProvider implements PaddingProvider {
    @Override
    public PaddingContext newInstance(int blockSize, int mode) {
        return new PaddingContextImpl(blockSize, mode);
    }

    public static class PaddingContextImpl implements PaddingContext {
        private final int blockSize;
        private final int mode;

        public PaddingContextImpl(int blockSize, int mode) {
            this.blockSize = blockSize;
            this.mode = mode;
        }

        @Override
        public byte[] doUpdate(byte[] buffer, int offset, int length) {
            if(offset == 0 && buffer.length == length)
                return buffer;
            return Arrays.copyOfRange(buffer, offset, offset + length);
        }

        @Override
        public byte[] doFinal() {
            return new byte[0];
        }
    }
}
