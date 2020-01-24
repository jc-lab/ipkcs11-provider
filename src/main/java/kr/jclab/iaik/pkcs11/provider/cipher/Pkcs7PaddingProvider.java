package kr.jclab.iaik.pkcs11.provider.cipher;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class Pkcs7PaddingProvider implements PaddingProvider {
    @Override
    public PaddingContext newInstance(int blockSize, int mode) {
        return new PaddingContextImpl(blockSize, mode);
    }

    public static class PaddingContextImpl implements PaddingContext {
        private final int blockSize;
        private final int mode;

        private int nonAlignLength = 0;
        private ByteBuffer padBuffer;

        public PaddingContextImpl(int blockSize, int mode) {
            this.blockSize = blockSize;
            this.mode = mode;
            this.padBuffer = ByteBuffer.allocate(blockSize);
            this.padBuffer.flip();
        }

        @Override
        public byte[] doUpdate(byte[] buffer, int offset, int length) {
            if(this.mode == Cipher.ENCRYPT_MODE) {
                this.nonAlignLength = (this.nonAlignLength + length) % this.blockSize;
                if(offset == 0 && buffer.length == length)
                    return buffer;
                return Arrays.copyOfRange(buffer, offset, offset + length);
            }else{
                ByteBuffer concatedBuffer = ByteBuffer.allocate(this.padBuffer.remaining() + length);
                concatedBuffer.put(this.padBuffer);
                concatedBuffer.put(buffer, offset, length);
                concatedBuffer.flip();
                int writableLength = concatedBuffer.remaining() - this.blockSize;
                byte[] outBuffer = null;
                if(writableLength > 0) {
                    outBuffer = new byte[writableLength];
                    concatedBuffer.get(outBuffer);
                }
                this.padBuffer.clear();
                this.padBuffer.put(concatedBuffer);
                this.padBuffer.flip();
                return outBuffer;
            }
        }

        @Override
        public byte[] doFinal() {
            if(this.mode == Cipher.ENCRYPT_MODE) {
                int pad = (this.nonAlignLength == 0) ? this.blockSize : this.blockSize - this.nonAlignLength;
                byte[] outBuffer = new byte[pad];
                for (int i = 0; i < pad; i++) {
                    outBuffer[i] = (byte) pad;
                }
                return outBuffer;
            }else{
                int padSize = this.padBuffer.array()[this.padBuffer.arrayOffset() + this.blockSize - 1] & 0xff;
                byte[] buffer = new byte[this.blockSize - padSize];
                this.padBuffer.get(buffer);
                return buffer;
            }
        }
    }
}
