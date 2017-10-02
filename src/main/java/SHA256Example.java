import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;

public class SHA256Example {

	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		SHA256Example sha256 = new SHA256Example(); 
		String hash = sha256.encodePassword("12345");
		System.out.println("hash=" + hash);

		for (int i=0; i<10;i++) {
			long start = System.currentTimeMillis();
			boolean b = sha256.isPasswordValid(hash, "12345");
			long end = System.currentTimeMillis();
			System.out.println("isvalid=" + b + ": " + (end-start) + " ms");
		}
	}

	private static final ShaPasswordEncoder ENCODER             = new ShaPasswordEncoder(256);
	private static final Pattern            HASH_FORMAT_PATTERN = Pattern.compile("\\{.+\\$(\\d+)\\$(.+)\\}.+"); // {Algorithmus$Iterationen$Salt}Hash
	private static final String             HASH_FORMAT         = "{%s$%d$%s}%s";                               // {Algorithmus$Iterationen$Salt}Hash

	private int                             iterations          = 5000;

	public String encodePassword(final String rawPass) {
		return encode(rawPass, iterations, String.valueOf(RandomStringUtils.randomAlphanumeric(10)));

	}

	private String encode(final String rawPass, final int iterations, final String salt) {
		// Salt darf maximal 10 Zeichen lang sein
		final String tailoredSalt;
		if (salt.length() > 10) {
			tailoredSalt = salt.substring(0, 10);
		}
		else {
			tailoredSalt = salt;
		}

		String hash = StringUtils.isEmpty(rawPass) ? "" : rawPass;
		boolean toogle = true; // Steuert ob das Password oder der Salt zum Erstellen des naechsten Hash-Wertes verwendet wird

		for (int i = 0; i < iterations; i++) {
			final String currentSalt;
			if (toogle) {
				currentSalt = tailoredSalt;
			}
			else {
				currentSalt = rawPass;
			}
			hash = ENCODER.encodePassword(hash, currentSalt);
			toogle = !toogle;
		}
		return String.format(HASH_FORMAT, ENCODER.getAlgorithm(), iterations, tailoredSalt, hash);
	}

	public boolean isPasswordValid(final String encPass, final String rawPass) {
		boolean ret = false;

		if (encPass != null && !encPass.isEmpty()) {
			final Matcher matcher = HASH_FORMAT_PATTERN.matcher(encPass);
			if (matcher.find()) {
				final int steps = Integer.valueOf(matcher.group(1));
				final String salt = matcher.group(2);
				ret = encode(rawPass, steps, salt).equals(encPass);
			}
		}

		return ret;
	}

	/**
	 * Default: 5000
	 * 
	 * @return Anzahl an Iterationen, die durchgefuehrt werden
	 */
	public int getIterations() {
		return iterations;
	}

	/**
	 * Aendert die Anzahl an durchgefuehrten Iterationen zur Bildung des
	 * Hashwertes.
	 * <p/>
	 * Default: 5000
	 * 
	 * @param iterations Anzahl an Iterationen, die durchgefuehrt werden
	 *          sollen
	 */
	public void setIterations(final int iterations) {
		this.iterations = iterations;
	}

}
