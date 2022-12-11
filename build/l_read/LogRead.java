package l_read;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
import java.util.TreeMap;
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

class LogRead {
	// Encryption algorithm used
	private static String algorithmString = "AES/CBC/PKCS5Padding";
	private static boolean integrityViolation = false;

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

		if (!Pattern.matches("[a-zA-Z0-9 /.-]+", Params))
			checkValid = false;
		if (!Params.contains("-K"))
			checkValid = false;
		if (Params.contains("-R") && !((Params.contains("-E") && !Params.contains("-G"))
				|| (!Params.contains("-E") && Params.contains("-G"))))
			checkValid = false;
		if (!(Params.split("-K").length < 3))
			checkValid = false; // prevents multiple occurences of same parameter.
		if (!(Params.split("-K").length < 3 && Params.split("-T").length < 3 && Params.split("-S").length < 3
				&& Params.split("-R").length < 3 && Params.split("-E").length < 3 && Params.split("-G").length < 3
				&& Params.split("-G").length < 3))
			checkValid = false;
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

	public static List<LogData> getLogList(String log) {
		List<String> dataList = Arrays.asList(log.split("\\R"));
		Collections.reverse(dataList); // reversing the log
		List<LogData> LogList = new ArrayList<>();
		for (String logline : dataList) {
			LogList.add(new LogData(logline));
		}
		return LogList;
	}

	public static boolean readLogState(String[] args) {

		if (!validParams(args)) {
			return false;
		}

		LogData objData = new LogData();
		if (!extractParamList(args, objData)) {
			return false;
		}

		try {
			if (new File(args[args.length - 1]).isFile()) {
				String pwdString = new String();
				File f = new File(args[args.length - 1]);
				Scanner reader = new Scanner(f);
				objData.setSalt(reader.nextLine());
				objData.setIV(reader.nextLine());
				pwdString = objData.getToken();
				String encryptedLog = reader.nextLine();
				reader.close();
				String decryptedLog = decrypt(algorithmString, encryptedLog,
						getPasswordBasedKey(algorithmString, 128, pwdString.toCharArray(), objData),
						new IvParameterSpec(Salting.decodeHexString(objData.getIV())));

				List<LogData> logList = getLogList(decryptedLog);
				HashMap<Integer, String> gRooms = new HashMap<Integer, String>();
				gRooms.put(-2, "nobody");
				HashMap<Integer, String> eRooms = new HashMap<Integer, String>();
				eRooms.put(-2, "nobody");
				TreeMap<Integer, String> Rooms = new TreeMap<Integer, String>();
				Rooms.put(-2, "nobody");
				for (LogData Log : logList) {
					if (Log.geteName() != null) {

						boolean checkRoom = false;
						List<String> eRoomValues = new ArrayList<String>(eRooms.values());
						for (String eNames : eRoomValues) {
							List<String> eNameList = Arrays.asList(eNames.split(","));
							if (eNameList.contains(Log.geteName())) {
								checkRoom = true;
								break;
							}

						}
						if (!checkRoom) {
							if (!eRooms.containsKey(Log.getRoom())) {
								eRooms.put(Log.getRoom(), Log.geteName());

							} else {
								eRooms.put(Log.getRoom(), eRooms.get(Log.getRoom()) + "," + Log.geteName());
							}
							if (!Rooms.containsKey(Log.getRoom())) {
								Rooms.put(Log.getRoom(), Log.geteName());

							} else {
								Rooms.put(Log.getRoom(), Rooms.get(Log.getRoom()) + "," + Log.geteName());
							}

						}
					} else {
						boolean checkRoom = false;
						List<String> gRoomValues = new ArrayList<String>(gRooms.values());
						for (String gNames : gRoomValues) {
							List<String> gNameList = Arrays.asList(gNames.split(","));
							if (gNameList.contains(Log.getgName())) {
								checkRoom = true;
								break;
							}

						}
						if (!checkRoom) {
							if (!gRooms.containsKey(Log.getRoom())) {
								gRooms.put(Log.getRoom(), Log.getgName());
							} else {
								gRooms.put(Log.getRoom(), gRooms.get(Log.getRoom()) + "," + Log.getgName());
							}
							if (!Rooms.containsKey(Log.getRoom())) {
								Rooms.put(Log.getRoom(), Log.getgName());
							} else {
								Rooms.put(Log.getRoom(), Rooms.get(Log.getRoom()) + "," + Log.getgName());
							}

						}
					}
				}
				// eRooms.remove(-1);
				eRooms.remove(-2);
				// gRooms.remove(-1);
				gRooms.remove(-2);
				Rooms.remove(-1);
				Rooms.remove(-2);
				String guests = "";
				String employees = "";
				for (String gNames : gRooms.values()) {
					guests = guests + "," + gNames;
				}
				for (String eNames : eRooms.values()) {
					employees = employees + "," + eNames;
				}
				String[] guestList = guests.split(",");
				Arrays.sort(guestList);
				String[] employeeList = employees.split(",");
				Arrays.sort(employeeList);
				if (guestList.length > 0) {
					guestList = Arrays.copyOfRange(guestList, 1, guestList.length);
				}
				if (employeeList.length > 0) {
					employeeList = Arrays.copyOfRange(employeeList, 1, employeeList.length);
				}

				System.out.println(String.join(",", employeeList));
				System.out.print(String.join(",", guestList));
				String membersRoom;

				for (int Room : Rooms.keySet()) {
					membersRoom = Rooms.get(Room);
					String[] membersRoomList = membersRoom.split(",");
					Arrays.sort(membersRoomList);
					membersRoom = String.join(",", membersRoomList);
					System.out.print("\n" + Room + ": " + membersRoom);
				}

			} else {
				return false;
			}
		} catch (Exception e) {
			integrityViolation = true;
			return false;
		}

		return true;
	}

	public static boolean readMemberRoom(String[] args) {

		if (!validParams(args)) {
			return false;
		}

		LogData objData = new LogData();
		if (!extractParamList(args, objData)) {
			return false;
		}

		try {
			String pwdString = new String();
			File f = new File(args[args.length - 1]);
			Scanner reader = new Scanner(f);
			objData.setSalt(reader.nextLine());
			objData.setIV(reader.nextLine());
			pwdString = objData.getToken();
			String encryptedLog = reader.nextLine();
			reader.close();
			String decryptedLog = decrypt(algorithmString, encryptedLog,
					getPasswordBasedKey(algorithmString, 128, pwdString.toCharArray(), objData),
					new IvParameterSpec(Salting.decodeHexString(objData.getIV())));

			List<LogData> logList = getLogList(decryptedLog);
			Collections.reverse(logList);
			List<Integer> roomSet = new ArrayList<Integer>();
			if (objData.geteName() != null) {
				for (LogData Log : logList) {
					if (objData.geteName().equals(Log.geteName())) {
						roomSet.add(Log.getRoom());
					}
				}
			} else if (objData.getgName() != null) {
				for (LogData Log : logList) {
					if (objData.getgName().equals(Log.getgName())) {
						roomSet.add(Log.getRoom());
					}
				}
			} else {
				return false;
			}
			roomSet.removeAll(Arrays.asList(-1));
			roomSet.removeAll(Arrays.asList(-2));
			for (Integer i = 0; i < roomSet.size(); i++) {
				if (i != roomSet.size() - 1) {
					System.out.print(roomSet.get(i) + ",");
				} else {
					System.out.print(roomSet.get(i));
				}
			}

		} catch (Exception e) {
			integrityViolation = true;
			System.out.println("integrity violation");
			return false;
		}

		return true;
	}

	public static void main(String args[]) {

		if (args.length <4){
			System.out.print("invalid");
			System.exit(255);
		}
		boolean validCommand = true;
		String argsString = String.join(" ", args);

		try {
			if (argsString.contains("-S") && !argsString.contains("-R") && !argsString.contains("-I")
					&& !argsString.contains("-T")) {
				validCommand = readLogState(args);
			} else if (argsString.contains("-R") && !argsString.contains("-S") && !argsString.contains("-I")
					&& !argsString.contains("-T")) {
				validCommand = readMemberRoom(args);
			} else if (argsString.contains("-I")
					|| argsString.contains("-T")) {
						System.out.println("unimplemented");
			} else {
				validCommand = false;
			}
		} catch (Exception e) {
			validCommand = false;

		}

		if (validCommand) {
			System.exit(0);
		} else {
			System.out.print("invalid");
			System.exit(255);
		}
	}
}
