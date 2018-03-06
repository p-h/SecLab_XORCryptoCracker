import java.io.*;

/**
 * Application for XOR-ing a file with a given key.
 * Works only for keys whose length is a multiple of 8 bits.
 * <p>
 * Usage:<br>
 * <tt>  XorWithKey inputfile outputfile keybyte1 ... keybyteN</tt>
 * <p>
 * Arguments:<br>
 * <ul>
 * <li>inputfile: The file to be XOR-ed with the key
 * <li>outputfile: Where to store the resulting file
 * <li>keybyte: The key in hexadecimal form (e.g., A1 B2 C3 11 )
 * </ul>
 * <p>
 *
 * @author tebe
 */
public class XorWithKeyApp {
    private static int[] key;
    private static String inputfile;
    private static String outputfile;

    /**
     * Main method of the application
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

    private static void run() throws IOException {
        BufferedInputStream in = null;
        BufferedOutputStream out = null;
        try {
            in = new BufferedInputStream(new FileInputStream(inputfile));
            out = new BufferedOutputStream(new FileOutputStream(outputfile));

            int pos = 0;
            int byteValue = in.read();
            while (byteValue != -1) {
                out.write(byteValue ^ key[pos]);
                pos = (pos + 1) % key.length;
                byteValue = in.read();
            }
        } finally {
            if (in != null)
                in.close();
            if (out != null)
                out.close();
        }
    }

    private static void usage() {
        System.out
                .println("Usage: XorWithKey inputfile outputfile keybyte1 ... keybyteN");
    }

    /**
     * Checks and parses the command line arguments.
     *
     * @param args Command line arguments
     * @return true, if the arguments could be parsed
     */
    private static boolean parseCommandLineParameters(String args[]) {
        if (args.length > 2) {
            try {
                inputfile = args[0];
                outputfile = args[1];
                key = new int[args.length - 2];
                for (int i = 2; i < args.length; i++) {
                    key[i - 2] = Integer.parseInt(args[i], 16);
                }
                return true;
            } catch (NumberFormatException e) {
                System.out.println(e.getMessage());
            }
        }
        return false;
    }

}