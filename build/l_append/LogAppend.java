package l_append;

import java.io.File;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
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

	public LogData() {
		Time = -1;
		Room = -2;
		this.filePath = null;
		Token = null;
		this.eName = null;
		this.gName = null;
		Event = null;
		Salt = null;
		IV = null;
	}

	@Override
	public String toString() {
		return "LogData [Time=" + Time + ", Room=" + Room + ", eName=" + eName + ", gName="
				+ gName + ", Event=" + Event + "]";
	}

	// function to deconstruct the logdata after decryption

	public LogData(String Data) {
		int i;
		String temp;
		i = Data.indexOf("Time");
		Time = Integer.parseInt(Data.substring(i + 5, Data.indexOf(",", i + 5)));
		i = Data.indexOf("Room");
		temp = new String(Data.substring(i + 5, Data.indexOf(",", i + 5)));
		Room = Integer.parseInt(temp);
		i = Data.indexOf("eName");
		temp = new String(Data.substring(i + 6, Data.indexOf(",", i + 5)));
		if (!temp.equals("null")) {
			eName = temp;
		}
		i = Data.indexOf("gName");
		temp = new String(Data.substring(i + 6, Data.indexOf(",", i + 5)));
		if (!temp.equals("null")) {
			gName = temp;
		}
		i = Data.indexOf("Event");
		temp = new String(Data.substring(i + 6, Data.indexOf("]", i + 5)));
		if (!temp.equals("null")) {
			Event = temp;
		}

	}

	int Time; // -T
	int Room; // -R, we will assume -1 for Gallery, -2 for outside gallery
	String filePath; // log
	String Token; // -K
	String eName; // -E
	String gName; // -G
	String Event; // Arrival or Leave (A or L)
	String Salt; // used to generate AES password with the Token, random for each log
	String IV; // IV for AES, random for each log

	// Getters and Setters

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

// Set of static functiond wrapped in Salting class to convert between hex
// string and byte array
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

	// Encryption algorithm used
	private static String algorithmString = "AES/CBC/PKCS5Padding";

	// Generating secure password for AES using Token and random salt
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

	// Encryption function
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

	// Decryption function
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

	// validating the commandline parameters
	public static boolean validParams(String args[]) {
		boolean checkValid = true;
		String Params = String.join(" ", args);
		Params.replace("\\", "/");
		// [a-zA-Z0-9_/\\\\ .-] if we should include other than project directory for
		// log
		// files
		if (!Pattern.matches("[a-zA-Z0-9 /.-]+", Params))
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
				&& Params.split("-A").length < 3 && Params.split("-E").length < 3 && Params.split("-G").length < 3
				&& Params.split("-G").length < 3))
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

		if (!String.join(" ", args).contains("-R")) {
			data.setRoom(-1);
		}

		data.setFilePath(args[args.length - 1].replace("\\", "/")); // convert file path backslashes to forward slashes.

		return checkValid;

	}

	public static boolean validateLog(LogData newData, String log) {

		List<String> dataList = Arrays.asList(log.split("\\R"));
		Collections.reverse(dataList); // reversing the log
		List<LogData> LogList = new ArrayList<>();
		boolean newName = true;
		for (String logline : dataList) {
			LogList.add(new LogData(logline));
		}
		if (newData.geteName() != null) {
			for (LogData oldLog : LogList) {
				if (newData.geteName().equals(oldLog.geteName())) {
					newName = false;
					if (newData.getTime() > oldLog.getTime()) {
						if ((newData.getEvent().equals("L") && oldLog.getEvent().equals("A"))
								|| (newData.getEvent().equals("A") && oldLog.getEvent().equals("L"))
								|| oldLog.getRoom() == -1) {
							if (newData.getEvent().equals("A")) {
								if (oldLog.getRoom() == -1 && newData.getRoom() != -1) {
									return true;
								} else if (oldLog.getRoom() == -2 && newData.getRoom() == -1) {
									return true;
								} else {
									return false;
								}
							} else {

								if (oldLog.getRoom() == newData.getRoom() && newData.getRoom() != -1) {
									newData.setRoom(-1);
									return true;
								} else if (oldLog.getRoom() == -1) {
									newData.setRoom(-2);
									return true;
								} else {
									return false;
								}
							}
						} else {
							return false;
						}
					} else {
						return false;
					}

				}
			}

		} else if (newData.getgName() != null) {
			for (LogData oldLog : LogList) {
				if (newData.getgName().equals(oldLog.getgName())) {
					newName = false;
					if (newData.getTime() > oldLog.getTime()) {
						if ((newData.getEvent().equals("L") && oldLog.getEvent().equals("A"))
								|| (newData.getEvent().equals("A") && oldLog.getEvent().equals("L"))
								|| oldLog.getRoom() == -1) {
							if (newData.getEvent().equals("A")) {
								if (oldLog.getRoom() == -1 && newData.getRoom() != -1) {
									return true;
								} else if (oldLog.getRoom() == -2 && newData.getRoom() == -1) {
									return true;
								} else {
									return false;
								}
							} else {
								if (oldLog.getRoom() == newData.getRoom() && newData.getRoom() != -1) {
									newData.setRoom(-1);
									return true;
								} else if (oldLog.getRoom() == -1) {
									newData.setRoom(-2);
									return true;
								} else {
									return false;
								}
							}
						} else {
							return false;
						}
					} else {
						return false;
					}

				}
			}

		} else {
			return false;
		}

		if (newName) {
			if (newData.getRoom() == -1 && newData.getEvent().equals("A"))
				return true;
			else
				return false;
		}
		return true;

	}

	public static boolean executeCommand(String[] args, LogData objData) {
		try {
			String pwdString = new String();
			String finalLog = new String();
			if (validParams(args)) {
				if (extractParamList(args, objData)) {
					File f = new File(objData.getFilePath());
					if (f.exists() && f.isFile()) {
						Scanner reader = new Scanner(f);
						objData.setSalt(reader.nextLine());
						objData.setIV(reader.nextLine());
						pwdString = objData.getToken();
						String encryptedLog = reader.nextLine();
						reader.close();
						String decryptedLog = decrypt(algorithmString, encryptedLog,
								getPasswordBasedKey(algorithmString, 128, pwdString.toCharArray(), objData),
								new IvParameterSpec(Salting.decodeHexString(objData.getIV())));
						// validate if new log doesn't contradict previous data
						if (!validateLog(objData, decryptedLog))
							return false;
						// continues with log append if vallid log
						finalLog = decryptedLog + "\n" + objData.toString();
						//System.out.println(finalLog + "\nexecuted command");
						String encryptedString = encrypt(algorithmString, finalLog,
								getPasswordBasedKey(algorithmString, 128, pwdString.toCharArray(), objData),
								new IvParameterSpec(Salting.decodeHexString(objData.getIV())));
						f.createNewFile();
						PrintWriter writer = new PrintWriter(f);
						writer.println(objData.getSalt());
						writer.println(objData.getIV());
						writer.println(encryptedString);
						writer.close();

					} else {
						if (objData.getFilePath().contains("/")) {
							if (!f.getParentFile().isDirectory()) {
								return false;
							}
						}
						pwdString = objData.getToken();
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
					return false;
			} else
				return false;
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	public static void main(String args[]) {

		if (args.length == 0)
			System.exit(255);
		boolean validCommand = true;
		LogData objData = new LogData();
		String pwdString = new String();
		String finalLog = new String();
		List<String> argsList = new ArrayList<String>();

		try {
			if (!args[0].equals("-B")) {
				validCommand = executeCommand(args, objData);
			} else if (args[0].equals("-B") && (new File(args[1]).isFile())) {
				File batchFile = new File(args[1]);
				Scanner scanner = new Scanner(batchFile);
				boolean checkBatchCommand = true;
				while (scanner.hasNextLine()) {
					objData = new LogData();
					checkBatchCommand = executeCommand(scanner.nextLine().split(" "), objData);
					if (!checkBatchCommand) {
						validCommand = checkBatchCommand;
						//System.out.println("invalid");
					}
				}
				scanner.close();
			} else {
				validCommand = false;
			}
		} catch (Exception e) {
			validCommand = false;

		}

		if (validCommand) {
			System.exit(0);
		} else {
			System.exit(255);
		}
	}

}
