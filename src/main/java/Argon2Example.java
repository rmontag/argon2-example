import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Constants;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;

public class Argon2Example {

	public static void main(String[] args) {
		//	    System.out.println("Runtime.getRuntime().totalMemory()=" + Runtime.getRuntime().totalMemory()/1000 + " KB");
		//	    System.out.println("Runtime.getRuntime().freeMemory()=" + Runtime.getRuntime().freeMemory()/1000 + " KB");

		long beforeUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
		System.out.println("beforeUsedMem=" + beforeUsedMem/1000 + " KB");

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
			int parallelism = 1;

			// Hash password
			String hash = argon2.hash(iterations, memory, parallelism, password);
			System.out.println("hash  = " + hash);
			//		    String hash2 = argon2.hash(r, N, p, password);
			//		    System.out.println("hash2 = " + hash2);

			// Verify password
			long start = System.currentTimeMillis();
			boolean verify = argon2.verify(hash, password);
			long end = System.currentTimeMillis();
			System.out.println("verify(); took " + (end -start) + " ms");
			
			if (verify) {
				System.out.println("Hash matches password");
			} else {
				System.out.println("Hash doesn't match password");
			}

			if (argon2.verify(hash, "OTHER")) {
				System.out.println("Hash matches OTHER");
			} else {
				System.out.println("Hash doesn't match OTHER");
			}

			//		    long afterHashMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
			//		    System.out.println("afterHashMem=" + afterHashMem/1000 + " KB");
			//
			//		    long actualMemUsed=afterHashMem-beforeUsedMem;
			//		    System.out.println("actualMemUsed=" + actualMemUsed/1000 + " KB");

		} finally {
			// Wipe confidential data
			argon2.wipeArray(password);
		}

		long afterUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
		System.out.println("afterUsedMem=" + afterUsedMem/1000 + " KB");

		long actualMemUsed=afterUsedMem-beforeUsedMem;	    
		System.out.println("actualMemUsed=" + actualMemUsed/1000 + " KB");

	}

}
