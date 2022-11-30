package l_append;

import java.io.File;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class LogData {

	@Override
	public String toString() {
		return "LogData [Time=" + Time + ", Room=" + Room + ", filePath=" + filePath + ", eName=" + eName + ", gName="
				+ gName + ", Event=" + Event + "]";
	}

	int Time; // -T
	int Room; // -R, we will assume -1 for Gallery
	String filePath; // log
	String Token; // -K
	String eName; // -E
	String gName; // -G
	String Event; // Arrival or Leave (A or L)
	String Salt;
	String IV;

	public String getIV() {
		return IV;
	}

	public void setIV(String iV) {
		IV = iV;
	}

	public void setTime(int time) {
		Time = time;
	}

	public void setRoom(int room) {
		Room = room;
	}

	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}

	public void setToken(String token) {
		Token = token;
	}

	public void seteName(String eName) {
		this.eName = eName;
	}

	public void setgName(String gName) {
		this.gName = gName;
	}

	public void setEvent(String event) {
		Event = event;
	}

	public void setSalt(String salt) {
		this.Salt = salt;
	}

	public int getTime() {
		return Time;
	}

	public int getRoom() {
		return Room;
	}

	public String getFilePath() {
		return filePath;
	}

	public String getToken() {
		return Token;
	}

	public String geteName() {
		return eName;
	}

	public String getgName() {
		return gName;
	}

	public String getEvent() {
		return Event;
	}

	public String getSalt() {
		return Salt;
	}

}

class Salting {

	public static String byteToHex(byte num) {
		char[] hexDigits = new char[2];
		hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
		hexDigits[1] = Character.forDigit((num & 0xF), 16);
		return new String(hexDigits);
	}

	public static byte hexToByte(String hexString) {
		int firstDigit = toDigit(hexString.charAt(0));
		int secondDigit = toDigit(hexString.charAt(1));
		return (byte) ((firstDigit << 4) + secondDigit);
	}

	private static int toDigit(char hexChar) {
		int digit = Character.digit(hexChar, 16);
		if (digit == -1) {
			throw new IllegalArgumentException(
					"Invalid Hexadecimal Character: " + hexChar);
		}
		return digit;
	}

	public static String encodeHexString(byte[] byteArray) {
		StringBuffer hexStringBuffer = new StringBuffer();
		for (int i = 0; i < byteArray.length; i++) {
			hexStringBuffer.append(byteToHex(byteArray[i]));
		}
		return hexStringBuffer.toString();
	}

	public static byte[] decodeHexString(String hexString) {
		if (hexString.length() % 2 == 1) {
			throw new IllegalArgumentException(
					"Invalid hexadecimal String supplied.");
		}

		byte[] bytes = new byte[hexString.length() / 2];
		for (int i = 0; i < hexString.length(); i += 2) {
			bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
		}
		return bytes;
	}

}

class LogAppend {

	private static String algorithmString = "AES/CBC/PKCS5Padding";

	private static SecretKey getPasswordBasedKey(String cipher, int keySize, char[] password, LogData obj)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		byte[] salt;

		if (obj.getSalt() == null) {
			salt = new byte[100];
			SecureRandom random = new SecureRandom();
			random.nextBytes(salt);
			obj.setSalt(Salting.encodeHexString(salt));
		} else {
			salt = Salting.decodeHexString(obj.getSalt());
		}

		PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000, keySize);
		SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);

		return pbeKey;
	}

	private static IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	private static String encrypt(String algorithm, String input, SecretKey key,
			IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException,
			BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(algorithm);
		SecretKeySpec spec = new SecretKeySpec(key.getEncoded(), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, spec, iv);
		byte[] cipherText = cipher.doFinal(input.getBytes());
		return Base64.getEncoder()
				.encodeToString(cipherText);
	}

	public static String decrypt(String algorithm, String cipherText, SecretKey key,
			IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException,
			BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(algorithm);
		SecretKeySpec spec = new SecretKeySpec(key.getEncoded(), "AES");
		cipher.init(Cipher.DECRYPT_MODE, spec, iv);
		byte[] plainText = cipher.doFinal(Base64.getDecoder()
				.decode(cipherText));
		return new String(plainText);
	}

	public static boolean validParams(String args[]) {
		boolean checkValid = true;
		String Params = String.join(" ", args);
		// [a-zA-Z0-9/\\\\ .-] if we should include other than project directory for log
		// files
		if (!Pattern.matches("[a-zA-Z0-9 .-]+", Params))
			checkValid = false;
		if (!((Params.contains("-A") && !Params.contains("-L")) || (!Params.contains("-A") && Params.contains("-L"))))
			checkValid = false;
		if (!((Params.contains("-E") && !Params.contains("-G")) || (!Params.contains("-E") && Params.contains("-G"))))
			checkValid = false;
		if (!Params.contains("-K"))
			checkValid = false;
		if (!Params.contains("-T"))
			checkValid = false;
		if (!(Params.split("-K").length < 3 && Params.split("-T").length < 3 && Params.split("-L").length < 3
				&& Params.split("-A").length < 3 && Params.split("-E").length < 3 && Params.split("-G").length < 3))
			checkValid = false; // prevents multiple occurences of same parameter.
		return checkValid;
	}

	public static boolean extractParamList(String args[], LogData data) {

		int i = 0;
		boolean checkValid = true;
		while (i < args.length) {
			if (Character.toString(args[i].charAt(0)).equals("-")) {
				switch (args[i].charAt(1)) {
					case 'K':
						if (!args[i].equals("-K")) {
							checkValid = false;
							break;
						}
						i = i + 1;
						if (i >= args.length)
							return false;
						if (!Pattern.matches("[a-zA-Z0-9]+", args[i])) {
							checkValid = false;
							break;
						}
						data.setToken(args[i]);

						break;

					case 'T':
						if (!args[i].equals("-T")) {
							checkValid = false;
							break;
						}
						i = i + 1;
						if (i >= args.length)
							return false;
						if (!Pattern.matches("[0-9]+", args[i])) {
							checkValid = false;
							break;
						}
						data.setTime(Integer.parseInt(args[i]));

						break;

					case 'L':
						if (!args[i].equals("-L")) {
							checkValid = false;
							break;
						}

						data.setEvent("L");
						
						break;

					case 'A':
						if (!args[i].equals("-A")) {
							checkValid = false;
							break;
						}

						data.setEvent("A");

						break;

					case 'G':
						if (!args[i].equals("-G")) {
							checkValid = false;
							break;
						}
						i = i + 1;
						if (i >= args.length)
							return false;
						if (!Pattern.matches("[a-zA-Z]+", args[i])) {
							checkValid = false;
							break;
						}
						data.setgName(args[i]);

						break;
					case 'E':
						if (!args[i].equals("-E")) {
							checkValid = false;
							break;
						}
						i = i + 1;
						if (i >= args.length)
							return false;
						if (!Pattern.matches("[a-zA-Z]+", args[i])) {
							checkValid = false;
							break;
						}
						data.seteName(args[i]);

						break;

					case 'R':
						if (!args[i].equals("-R")) {
							checkValid = false;
							break;
						}
						i = i + 1;
						if (i >= args.length)
							return false;
						if (!Pattern.matches("[0-9]+", args[i])) {
							checkValid = false;
							break;
						}
						data.setRoom(Integer.parseInt(args[i]));

						break;
					default:
						break;
				}
			}
			if (!checkValid)
				return checkValid;
			i = i + 1;
		}

		data.setFilePath(args[args.length - 1]);

		return checkValid;

	}

	public static void main(String args[]) {

		if(args.length==0)
			System.exit(255);

		LogData objData = new LogData();
		String pwdString = new String();
		String finalLog = new String();
		List<String> argsList = new ArrayList<String>();

		try {
			if (!args[0].equals("-B")) {
				if (validParams(args)) {
					if (extractParamList(args, objData)) {
						File f = new File(objData.getFilePath());
						if (f.exists() && f.isFile()) {
							// authentication and appending
						} else {

							objData.setIV(Salting.encodeHexString(generateIv().getIV()));
							finalLog = objData.toString();
							String encryptedString = encrypt(algorithmString, finalLog,
									getPasswordBasedKey(algorithmString, 128, pwdString.toCharArray(), objData),
									new IvParameterSpec(Salting.decodeHexString(objData.getIV())));
							f.createNewFile();
							PrintWriter writer = new PrintWriter(f);
							writer.println(objData.getSalt());
							writer.println(objData.getIV());
							writer.println(encryptedString);
							writer.close();

						}
					} else
						System.exit(255);
				} else
					System.exit(255);
			} else {
				// code for handling batch files
			}
		} catch (Exception e) {
			System.out.println(e.toString());
		}

		// try {
		// System.out.println(getPasswordBasedKey(algorithmString, 128,
		// pwdString.toCharArray(), objData).toString());
		// System.out.println(objData.Salt);
		// objData.setIV(Salting.encodeHexString(generateIv().getIV()));
		// String encryptedString = encrypt(algorithmString, finalLog,
		// getPasswordBasedKey(algorithmString, 128, pwdString.toCharArray(), objData),
		// new IvParameterSpec(Salting.decodeHexString(objData.getIV())));
		// System.out.println("Encrypted String:" + encryptedString);
		// String decryptedString = decrypt(algorithmString, encryptedString,
		// getPasswordBasedKey(algorithmString, 128, pwdString.toCharArray(), objData),
		// new IvParameterSpec(Salting.decodeHexString(objData.getIV())));
		// System.out.println("Decrypted String:" + decryptedString);
		// } catch (Exception e) {
		// System.out.println(e.toString());;
		// }

		System.out.println("Executed");

		System.exit(0);
	}

}
