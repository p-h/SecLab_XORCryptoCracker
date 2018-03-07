import ch.zhaw.init.is.crypto.classic.ByteFrequencyTable;
import ch.zhaw.init.is.crypto.classic.ByteFrequencyTableHelpers;
import ch.zhaw.init.is.util.HexTools;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Optional;

/**
 * Application for cracking the encryption of files that have been
 * encrypted with the XOR method with key lengths much smaller than
 * the size of the plaintext. Cracking is based on the assumption
 * that there is a byte value in the plaintext which is significantly more
 * frequent than other byte values.
 * <p>
 * Usage:<br>
 * <tt>  XorCrackerApp file keylength</tt>
 * <p>
 * Arguments:<br>
 * <ul>
 * <li>file: The file to be cracked
 * <li>keylength: The length of the key in bytes
 * </ul>
 * <p>
 *
 * @author tebe
 */
public class XorCrackerApp {
    private int keylength;
    private String filename;
    private int mostFrequentCharacter;

    public XorCrackerApp(String filename, int keylength) {
        this(filename, keylength, 'e');
    }

    public XorCrackerApp(String filename, int keylength, int mostFrequentCharacter) {
        this.filename = filename;
        this.keylength = keylength;
        this.mostFrequentCharacter = mostFrequentCharacter;
    }

    /**
     * Main method of the application
     *
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        Optional<XorCrackerApp> app = parseCommandLineParametersToApp(args);
        app.ifPresentOrElse(a -> {
            try {
                a.run();
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }, XorCrackerApp::usage);
    }

    private static void usage() {
        System.out.println("Usage: XorCrackerApp file keylength");
    }

    /**
     * Checks and parses the command line arguments.
     *
     * @param args Command line arguments
     * @return true, if the arguments could be parsed
     */
    private static Optional<XorCrackerApp> parseCommandLineParametersToApp(String args[]) {
        if (args.length >= 2) {
            try {
                String filename = args[0];
                int keylength = Integer.parseInt(args[1]);

                if (args.length >= 3) {
                    int mostFrequent = (int) args[2].charAt(0);
                    return Optional.of(new XorCrackerApp(filename, keylength, mostFrequent));
                }

                return Optional.of(new XorCrackerApp(filename, keylength));
            } catch (NumberFormatException e) {
            }
        }
        return Optional.empty();
    }


    /**
     * Starts and controls the analysis process
     *
     * @throws IOException
     */
    private void run() throws IOException {
        try {
            System.out.println("Number of candidate keys: " + getNumberOfCandidateKeys());
            int[] key = getCandidateKey(filename, keylength, mostFrequentCharacter);
            System.out.println(HexTools.intArrayToHexString(key));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static int getNumberOfCandidateKeys() {
        return 1;
    }


    /**
     * Determines the key assuming the specified most frequent byte is the most frequent
     * byte in the plaintext and keylength is the true length of the key.
     *
     * @param filename          The name of the file to process
     * @param keylength         The key length in bytes
     * @param mostFrequentValue The assumed most frequent byte in the plaintext
     * @return The key
     * @throws IOException
     */
    private static int[] getCandidateKey(String filename, int keylength, int mostFrequentValue) throws IOException {
        DataInputStream inputStream = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));
        ByteFrequencyTable[] frequencyTable = ByteFrequencyTableHelpers.getFrequencyTableForKeyLength(keylength, inputStream);
        int[] key = new int[keylength];
        for (int i = 0; i < keylength; i++) {
            int maxHx = frequencyTable[i].getMostFrequentByte();
            key[i] = maxHx ^ mostFrequentValue;
        }
        return key;
    }
}
