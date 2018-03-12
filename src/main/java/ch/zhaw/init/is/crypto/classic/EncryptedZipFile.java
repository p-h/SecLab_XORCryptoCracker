package ch.zhaw.init.is.crypto.classic;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * @author tebe
 */
public class EncryptedZipFile {
    private static final byte[] ZIP_FILE_HEADER = {0x50, 0x4B, 0x03, 0x04};
    private ByteBuffer buffer = ByteBuffer.allocate(8);
    private byte[] encryptedZipFile;
    private byte[] decryptedZipFile;
    private ByteArrayInputStream inputStreamDecryptedZipFile;

    public static EncryptedZipFile create(String filename) throws IOException {
        EncryptedZipFile file = null;
        BufferedInputStream inputStream = null;
        try {
            inputStream = new BufferedInputStream(new FileInputStream(filename));
            file = create(inputStream);
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
        }

        return file;
    }

    public static EncryptedZipFile create(InputStream inputStream) throws IOException {
        EncryptedZipFile file = new EncryptedZipFile();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            int tempByte;
            while ((tempByte = inputStream.read()) != -1) {
                outputStream.write(tempByte);
            }

            file.encryptedZipFile = outputStream.toByteArray();
            file.decryptedZipFile = new byte[file.encryptedZipFile.length];
            file.inputStreamDecryptedZipFile = new ByteArrayInputStream(file.decryptedZipFile);
        } finally {
            outputStream.close();
        }

        return file;
    }

    private static boolean decryptAndCompareByte(int expectedValue, byte byteToDecryptAndTest, int keyByte) {
        return expectedValue == ((byteToDecryptAndTest ^ keyByte) & 0x000000FF);
    }

    private EncryptedZipFile() {
    }

    public EncryptedZipFile clone() {
        try (ByteArrayInputStream is = new ByteArrayInputStream(this.encryptedZipFile)) {
            return create(new ByteArrayInputStream(this.encryptedZipFile));
        } catch (IOException ignored) {
        }

        return null;
    }

    /**
     * @return Stream for accessing the raw bytes of the ZIPed and encrypted file
     */
    public DataInputStream getDataInputStream() {
        return new DataInputStream(new BufferedInputStream(new ByteArrayInputStream(encryptedZipFile)));
    }

    private void decrypt(int[] key) {
        int keyIndex = 0;
        for (int i = 0; i < encryptedZipFile.length; i++) {
            decryptedZipFile[i] = (byte) (encryptedZipFile[i] ^ key[keyIndex]);
            keyIndex = (keyIndex + 1) % key.length;
        }
    }

    private boolean isKeyValidHeuristics(int[] key) {
        //TODO: Insert reasonable Heuristics. Currently, the heuristics
        //      always returns true so that it does not filter candidate
        //      keys in a more efficient manner than decrypting the whole file
        //      and then trying to uncompress it.
        //
        //      Have a look at the {@link #decryptAndCompareByte} method.
        //      It might be useful when implementing a suitable heuristics.
        //
        //      Looking at other methods in this class might also help in
        //      finding a suitable approach.

        return true;
    }

    /**
     * Try to decrypt the file with the provided key.
     * Decryption is successful if decompression of the
     * decrypted file was successful.
     *
     * @param key The key
     * @return true, if decryption was successful
     */
    public boolean tryDecryption(int[] key) {
        if (!isKeyValidHeuristics(key)) {
            return false;
        }
        decrypt(key);
        inputStreamDecryptedZipFile.reset();
        ZipInputStream zip = new ZipInputStream(inputStreamDecryptedZipFile);
        try {
            ZipEntry ze = zip.getNextEntry();
            if (ze == null) {
                return false;
            }
            while (ze != null) {
                ze.getCrc();
                ze.getCompressedSize();
                ze.getName();
                ze = zip.getNextEntry();
            }
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            try {
                if (zip != null) {
                    zip.close();
                }
            } catch (IOException e) {
                return false;
            }
            zip = null;
        }
    }

    /**
     * Gets the first length bytes (prefix) from the decrypted file.
     * For useful results, {@link #isValidKey} must be called first with a
     * valid key.
     *
     * @param length The number of bytes to read
     * @return The first length bytes of the file header as an int-array,
     * containing the byte values
     */
    public int[] readFilePrefix(int length) {
        int[] filePrefix = new int[Math.min(length, decryptedZipFile.length)];
        for (int i = 0; i < filePrefix.length; i++) {
            filePrefix[i] = (int) decryptedZipFile[i] & 0x000000FF;
        }
        return filePrefix;
    }

    /**
     * Reads the file header of the decrypted ZIP file.
     * For useful results, {@link #isValidKey} must be called first with a
     * valid key.
     *
     * @return The information on the file header
     */
    public String getZipFileHeader() throws IOException {
        DataInputStream inputStream = null;
        String header = "";
        try {
            inputStream = new DataInputStream(new BufferedInputStream(new ByteArrayInputStream(decryptedZipFile)));
            header += "Local file header signature    = "
                    + Integer.toHexString(readInt(inputStream));
            header += System.lineSeparator();
            header += "Version needed to extract (>=) = "
                    + readShort(inputStream);
            header += System.lineSeparator();
            header += "General purpose bit flag       = "
                    + readShort(inputStream);
            header += System.lineSeparator();
            header += "Compression method             = "
                    + readShort(inputStream);
            header += System.lineSeparator();
            header += "File last modification time    = "
                    + readShort(inputStream);
            header += System.lineSeparator();
            header += "File last modification date    = "
                    + readShort(inputStream);
            header += System.lineSeparator();
            header += "CRC32                          = "
                    + Integer.toHexString(readInt(inputStream));
            header += System.lineSeparator();
            header += "Compressed size                = "
                    + readInt(inputStream);
            header += System.lineSeparator();
            header += "Uncompressed size              = "
                    + readInt(inputStream);
            header += System.lineSeparator();
            return header;
        } finally {
            if (inputStream != null)
                inputStream.close();
        }
    }

    private Short readShort(DataInputStream in) throws IOException {
        buffer.clear();
        buffer.order(ByteOrder.BIG_ENDIAN).putInt(in.readShort()).flip();
        return buffer.order(ByteOrder.LITTLE_ENDIAN).getShort();
    }

    private Integer readInt(DataInputStream in) throws IOException {
        buffer.clear();
        buffer.order(ByteOrder.BIG_ENDIAN).putInt(in.readInt()).flip();
        return buffer.order(ByteOrder.LITTLE_ENDIAN).getInt();
    }
}
