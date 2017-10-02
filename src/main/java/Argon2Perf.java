import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Constants;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;

public class Argon2Perf {

	public static void main(String[] args) {

		// Create instance
		// Defaults to:
		// - Argon2Types.ARGON2i = Argon2i
		// - Argon2Constants.DEFAULT_SALT_LENGTH = 16
		// - Argon2Constants.DEFAULT_HASH_LENGTH = 32
		Argon2 argon2 = Argon2Factory.create();

		// Read password from user
		char[] password = "12345".toCharArray();

		try {
			// Number of iterations
			int iterations = 100;
			// Sets memory usage to x kibibytes
			int memory = 64 * 1024;
			// Number of threads and compute lanes
			int parallelism = 2;

			// Hash password
			String hash = argon2.hash(iterations, memory, parallelism, password);
			System.out.println("hash  = " + hash);
			//		    String hash2 = argon2.hash(r, N, p, password);
			//		    System.out.println("hash2 = " + hash2);

			for (int i=0; i<10;i++) {
				// Verify password
				long start = System.currentTimeMillis();
				argon2.verify(hash, password);
				long end = System.currentTimeMillis();
				System.out.println("verify() took " + (end -start) + " ms");

			}

		} finally {
			// Wipe confidential data
			argon2.wipeArray(password);
		}

	}

}
