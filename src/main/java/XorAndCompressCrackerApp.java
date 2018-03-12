import ch.zhaw.init.is.crypto.classic.XorAndCompressCracker;
import ch.zhaw.init.is.util.HexTools;
import ch.zhaw.init.is.util.ProgressTask;

import java.io.IOException;
import java.util.Timer;

/**
 * Application for cracking the encryption of files that have been compressed
 * with ZIP (deflate) before they were encrypted with the XOR method with key
 * lengths much smaller than the size of the compressed plaintext.
 * <p>
 * Usage:<br>
 * <tt>  XorAndCompressCrackerApp file keylength depth</tt>
 * <p>
 * Arguments:<br>
 * <ul>
 * <li>file: The encrypted ZIP file to be cracked
 * <li>keylength: The length of the key in bytes
 * <li>depth: The search depth (top 'depth' most frequent bytes per key byte)
 * </ul>
 * <p>
 * Note: If the combination of key length and depth would result in testing more
 * than {@value #MAX_TRIALS}, nothing is done.
 *
 * @author tebe
 */
public class XorAndCompressCrackerApp {
    private static final long MAX_TRIALS = 68719476736L; // 2^36
    private static final int PROGRESS_INTERVAL = 5000; // in ms
    private static int keylength;
    private static int depth;
    private static String filename;

    /**
     * Main method of the application.
     *
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        if (parseCommandLineParameters(args)) {
            try {
                run();
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        } else {
            usage();
        }
    }

    private static void usage() {
        System.out
                .println("Usage: XorAndCompressCrackerApp file keylength depth ");
    }

    /**
     * Checks and parses the command line arguments.
     *
     * @param args Command line arguments
     * @return true, if the arguments could be parsed
     */
    private static boolean parseCommandLineParameters(String args[]) {
        System.out.println("available processors: " + Runtime.getRuntime().availableProcessors());
        if (args.length == 3) {
            try {
                filename = args[0];
                keylength = Integer.parseInt(args[1]);
                depth = Integer.parseInt(args[2]);
                return true;
            } catch (NumberFormatException e) {
            }
        }
        return false;
    }

    /**
     * Starts and controls the analysis process
     *
     * @throws IOException
     */
    private static void run() throws IOException {
        XorAndCompressCracker c = new XorAndCompressCracker(filename);
        printQueryInformation(c);
        long candidateKeys = c.getNumberOfCandidateKeys(keylength, depth);
        if (candidateKeys < MAX_TRIALS) {
            Timer timer = new Timer();
            timer.schedule(new ProgressTask(c), PROGRESS_INTERVAL, PROGRESS_INTERVAL);
            int[] key = c.determineKey(keylength, depth);
            timer.cancel();
            printResult(key);
        } else {
            printTooManyCandidateKeys(candidateKeys);
        }

    }

    private static void printTooManyCandidateKeys(long candidateKeys) {
        System.out.println("Too many candidate keys to check: " + candidateKeys
                + "(Limit: " + MAX_TRIALS + ")");

    }

    private static void printQueryInformation(XorAndCompressCracker c) {
        System.out.println("Analyzing file: " + filename);
        System.out.println("Number of candidate keys: "
                + c.getNumberOfCandidateKeys(keylength, depth)
                + " at key length " + keylength + " and search depth " + depth);
    }

    private static void printResult(int[] key) {
        if (key != null) {
            System.out.println("Key: " + HexTools.intArrayToHexString(key));
        } else {
            System.out
                    .println("No valid key found. Key too long? Increasing the search depth might help.");
        }
    }

}
