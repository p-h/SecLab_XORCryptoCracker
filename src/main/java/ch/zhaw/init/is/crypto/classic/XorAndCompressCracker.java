package ch.zhaw.init.is.crypto.classic;

import ch.zhaw.init.is.util.ProgressInfo;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Optional;
import java.util.Spliterators;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static java.util.Spliterator.DISTINCT;
import static java.util.Spliterator.NONNULL;

public class XorAndCompressCracker implements ProgressInfo {
    private EncryptedZipFile encryptedZipFile;
    private AtomicLong numberOfKeysTested = new AtomicLong();
    private long totalNumberOfKeysToTest;


    public XorAndCompressCracker(String filename) throws IOException {
        encryptedZipFile = EncryptedZipFile.create(filename);
    }


    /**
     * Determines the key of an encrypted ZIP file assuming the specified key length and search depth.
     *
     * @param keylength The key length in bytes
     * @param depth     The search depth (top 'depth' most frequent bytes per key byte)
     * @return The key or null, if none was found
     * @throws IOException
     */
    public int[] determineKey(int keylength, int depth) throws IOException {
        totalNumberOfKeysToTest = getNumberOfCandidateKeys(keylength, depth);
        numberOfKeysTested.set(0);
        ByteFrequencyTable[] frequencyTable = getFrequencyTableForKeyLength(keylength);
        int[] key = null;

        ExecutorService pool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        KeyGenerator keyGenerator = new KeyGenerator(frequencyTable, depth, 0);
        keyGenerator.getKeyStream()
                .map(k -> CompletableFuture.supplyAsync(() -> {
                    numberOfKeysTested.incrementAndGet();
                    if (encryptedZipFile.clone().tryDecryption(k)) return Optional.of(k);
                    else return Optional.empty();
                }, pool))
                .map(f -> {
                    try {
                        return f.get();
                    } catch (InterruptedException | ExecutionException e) {
                    }

                    return Optional.empty();
                })
                .filter(Optional::isPresent)
                .findFirst();


        return null;
    }

    private ByteFrequencyTable[] getFrequencyTableForKeyLength(int keylength) throws IOException {
        DataInputStream inputStream = encryptedZipFile.getDataInputStream();
        return ByteFrequencyTableHelpers.getFrequencyTableForKeyLength(keylength, inputStream);
    }


    /**
     * Returns the number of candidate keys for a given key length
     * and search depth. Uses the top 'depth' most frequent bytes
     *
     * @param keylength The length of the key in bytes
     * @param depth     The search depth (top 'depth' most frequent bytes)
     * @return The number of candidate keys
     */
    public long getNumberOfCandidateKeys(int keylength, int depth) {
        return (long) (256 * Math.pow(depth, keylength));
    }


    /* (non-Javadoc)
     * @see ch.zhaw.init.is.util.ProgressInfo#getProgressAbsolute()
     */
    @Override
    public double getProgressAbsolute() {
        return this.numberOfKeysTested.get();
    }


    /* (non-Javadoc)
     * @see ch.zhaw.init.is.util.ProgressInfo#getProgressInPercent()
     */
    @Override
    public double getProgressInPercent() {
        return numberOfKeysTested.get() / (double) totalNumberOfKeysToTest * 100;
    }


    /* (non-Javadoc)
     * @see ch.zhaw.init.is.util.ProgressInfo#getUnit()
     */
    @Override
    public String getUnit() {
        return "trials";
    }
}


/**
 * Helper class to generate different candidate keys. It is based on the
 * assumption that when generating the byte frequency distributions per key
 * byte from the ciphertext, then the most frequent byte in the compressed
 * plaintext should correspond to one of the most frequent bytes in all of the
 * byte frequency distributions generated from the ciphertext.
 *
 * @author tebe
 */
class KeyGenerator {
    private int[][] candidates;
    private int[] currentCandidateCombination;
    private int numberOfCandidatesPerKeyByte;
    private boolean allCandidatesTested;
    private int mostFrequentByteInPlaintext;

    /**
     * Constructor. It generates a 2D array with size keylength *
     * numberOfCandidatesPerKeyByte and stores it in the variable candidates.
     * For each of the key bytes, the array contains the numberOfCandidatesPerKeyByte
     * most frequent ciphertext bytes. This 2D array is then used as the basis to
     * determine different candidate keys by using the other methods in this class.
     * <p>
     * The next combination of the ciphertext bytes to be tested is determined by
     * the value of the array currentCandidateCombination (see method
     * getNextCandidatedKey below). The constructor creates this array and sets it
     * to [0 0 0 0 0 0] (assuming a keylength of 6).
     *
     * @param frequencyTable               The frequency table (per key byte) of the ciphertext
     * @param numberOfCandidatesPerKeyByte The number of candidates to consider per key byte
     *                                     (e.g. if equal to 4, then the 4 most frequent ciphertext
     *                                     bytes are considered per key byte)
     * @param mostFrequentByte             The assumed most frequent byte in the plaintext
     */
    public KeyGenerator(ByteFrequencyTable[] frequencyTable,
                        int numberOfCandidatesPerKeyByte, int mostFrequentByte) {
        this.numberOfCandidatesPerKeyByte = numberOfCandidatesPerKeyByte;
        this.mostFrequentByteInPlaintext = mostFrequentByte;
        candidates = new int[frequencyTable.length][];
        currentCandidateCombination = new int[frequencyTable.length];

        // Creates the 2D array which contains the numberOfCandidatesPerKeyByte
        // most frequent ciphertext bytes per key byte.
        for (int keyIndex = 0; keyIndex < frequencyTable.length; keyIndex++) {
            candidates[keyIndex] = frequencyTable[keyIndex]
                    .getMostFrequentBytes(numberOfCandidatesPerKeyByte);
        }
    }

    /**
     * Returns the next candidate key. To do this, the current value of
     * currentCandidateCombination is taken to determine the next combination of
     * ciphertext bytes to be tested. For instance (assuming a keylength of 6),
     * if currentCandidateCombination corresponds to [0 3 1 3 0 2], this means that
     * for the first ciphertext byte, the most frequent byte is taken, for the second
     * ciphertext byte, the 4th-most frequent byte is chosen, for the third ciphertext
     * byte, the 2nd-most frequent byte is chosen and so on.
     * <p>
     * The corresponding candidate key is then determined by XOR-ing these ciphertext
     * bytes with the assumed most frequent value in the plaintext.
     *
     * @return The candidate key or null if all candidate keys have been returned
     */
    public int[] getNextCandidateKey() {
        if (allCandidatesTested) {
            return null;
        }
        int[] key = new int[candidates.length];
        for (int keyByte = 0; keyByte < key.length; keyByte++) {
            key[keyByte] = candidates[keyByte][currentCandidateCombination[keyByte]]
                    ^ mostFrequentByteInPlaintext;
        }
        updateCandidateCombination();
        return key;
    }

    public Stream<int[]> getKeyStream() {
        return StreamSupport.stream(new Spliterators.AbstractSpliterator<int[]>(Long.MAX_VALUE, DISTINCT | NONNULL) {
            @Override public boolean tryAdvance(Consumer<? super int[]> action) {
                int[] key = getNextCandidateKey();

                if (key == null) return false;
                else action.accept(key);

                return true;
            }
        }, false);
    }


    /**
     * Switches to the next combination of ciphertext bytes to be tested by updating
     * currentCandidateCombination. With each call of the method, the next combination
     * is determined based on the current combination. For instance (assuming a keylength
     * of 6 and numberOfCandidatesPerKeyByte = 4), the sequence is [0 0 0 0 0 0],
     * [0 0 0 0 0 1], [0 0 0 0 0 2], [0 0 0 0 0 3], [0 0 0 0 1 0], [0 0 0 0 1 1] and so on.
     * Overall, all possible combinations from [0 0 0 0 0 0] to [3 3 3 3 3 3] will be used
     * exactly once, which guarantees that all combinations will be tested.
     */
    private void updateCandidateCombination() {
        int index = currentCandidateCombination.length - 1;
        while (index >= 0
                && currentCandidateCombination[index] == numberOfCandidatesPerKeyByte - 1) {
            currentCandidateCombination[index] = 0;
            index--;
        }
        if (index < 0) {
            allCandidatesTested = true;
        } else {
            currentCandidateCombination[index]++;
        }
    }

}