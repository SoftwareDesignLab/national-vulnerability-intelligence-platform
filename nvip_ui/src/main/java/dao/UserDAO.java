/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the �Software�), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package dao;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDate;
import java.time.LocalDateTime;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import data.DBConnect;
import model.User;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class UserDAO {
	private static String dbType = DBConnect.getDatabaseType();
	private static Logger logger = LogManager.getLogger(UserDAO.class);

	/**
	 * Function that Hash Encrypts passwords that are inputed into
	 * the system
	 * @param password
	 * @param salt
	 * @param iterations
	 * @param keyLength
	 * @return
	 */
	public static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength) {

		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
			SecretKey key = skf.generateSecret(spec);
			byte[] res = key.getEncoded();
			return res;
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Function that generates Hex String for password hashing
	 * @param s
	 * @return
	 */
	/* s must be an even-length string. */
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * Checks if a user with the given name exists in the NVIP Database,
	 * if so, return true...return false otherwise
	 * @param conn
	 * @param userName
	 * @return
	 */
	private static boolean checkUserExistance(Connection conn, String userName) {
		boolean userExist = false;
		try (PreparedStatement stmt = conn.prepareStatement("SELECT COUNT(u.user_id) AS userCount, user_id FROM user u " + " WHERE u.user_name = ?")) {

			stmt.setString(1, userName);

			ResultSet rs = stmt.executeQuery();

			while (rs.next()) {
				int userCount = rs.getInt("userCount");
				if (userCount >= 1) {
					return true;
				} else {
					return false;
				}
			}

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return userExist;
	}

	/**
	 * Create User function that takes the new user info ad inserts it into
	 * the NVIP Database
	 * @param conn
	 * @param user
	 * @param password_hash
	 * @return
	 */
	private static int createUser(Connection conn, User user, String password_hash) {
		try (PreparedStatement stmt = conn.prepareStatement("INSERT user SET user_name=?, password_hash=?, first_name = ?, " + "last_name=?, email=?, role_id=?, registered_date=?;")) {

			stmt.setString(1, user.getUserName());
			stmt.setString(2, password_hash);
			stmt.setString(3, user.getFirstName());
			stmt.setString(4, user.getLastName());
			stmt.setString(5, user.getEmail());
			stmt.setInt(6, user.getRoleId());
			stmt.setTimestamp(7, Timestamp.valueOf(LocalDateTime.now()));

			int rs = stmt.executeUpdate();

			return rs;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;
	}

	/**
	 * Function that updates a user's token once they login
	 * When the token expires, the user be forced to logout
	 * @param conn
	 * @param userName
	 * @param token
	 * @param loginDate
	 * @param expirationDate
	 * @return
	 */
	private static int updateToken(Connection conn, String userName, String token, LocalDateTime loginDate, LocalDateTime expirationDate) {
		try (PreparedStatement stmt = conn.prepareStatement("UPDATE user SET token = ?, token_expiration_date = ?, " + "last_login_date = ? WHERE user_name = ?;")) {

			stmt.setString(1, token);
			stmt.setTimestamp(2, Timestamp.valueOf(loginDate));
			stmt.setTimestamp(3, Timestamp.valueOf(expirationDate));
			stmt.setString(4, userName);

			int rs = stmt.executeUpdate();

			return rs;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;
	}

	/**
	 * Helper function for obtaining RoleID and ExpirationDate info,
	 * Calls to NVIP Database for users with given token and name,
	 * Checks for duplicates if any.
	 * @param conn
	 * @param userName
	 * @param token
	 * @return
	 */
	private static User getRoleIDandExpirationDate(Connection conn, String userName, String token) {

		try (PreparedStatement stmt = conn.prepareStatement("SELECT COUNT(u.user_id) AS userCount, user_id, role_id, token_expiration_date FROM user u " + 
		" WHERE u.user_name = ? GROUP BY user_id")) {

			stmt.setString(1, userName);
			//stmt.setString(2, token);

			ResultSet rs = stmt.executeQuery();

			while (rs.next()) {
				int userCount = rs.getInt("userCount");
				if (userCount == 1) {
					int role_id = rs.getInt("role_id");
					int user_id = rs.getInt("user_id");
					LocalDateTime expirationDate = rs.getTimestamp("token_expiration_date").toLocalDateTime();
					User userInDB = new User(user_id, null, userName, null, null, null, null, role_id, expirationDate);
					rs.close();
					return userInDB;
				} else {
					rs.close();
					return null;
				}
			}
		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Function that collects User info for Servlets that require to
	 * verify user and role_id info
	 * @param userName
	 * @param token
	 * @return
	 */
	public static User getRoleIDandExpirationDate(String userName, String token) {

		try (Connection conn = DBConnect.getConnection()) {

			User user = getRoleIDandExpirationDate(conn, userName, token);
			return user;

		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * TODO: Could we possibly see if there's a way to merge this function with getRoleIDandExpirationDate
	 * (i.e. a function that just grabs user data with provided parameters)
	 * 
	 * Helper function for Login that queries for User in NVIP Database 
	 * @param conn
	 * @param userName
	 * @return
	 */
	private static User login(Connection conn, String userName) {
		
		try (PreparedStatement stmt = conn.prepareStatement("SELECT COUNT(u.user_id) AS userCount, user_id, password_hash, role_id, first_name, " 
		+ "last_name FROM user u WHERE u.user_name = ? GROUP BY u.user_id")) {
			stmt.setString(1, userName);

			ResultSet rs = stmt.executeQuery();

			while (rs.next()) {
				int userCount = rs.getInt("userCount");
				if (userCount == 1) {
					int role_id = rs.getInt("role_id");
					String first_name = rs.getString("first_name");
					String last_name = rs.getString("last_name");
					String password_hash = rs.getString("password_hash");
					int user_id = rs.getInt("user_id");
					User userInDB = new User(user_id, null, userName, first_name, last_name, null, password_hash, role_id, null);
					rs.close();
					return userInDB;
				} else {
					rs.close();
					return null;
				}
			}
		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Login function called by LoginServlet (GET Request),
	 * Verifies passwords match and creates token for user
	 * @param userName
	 * @param password
	 * @return
	 */
	public static User login(String userName, String password) {
		// Password Hashing Logic

		try (Connection conn = DBConnect.getConnection()) {

			User user = login(conn, userName.toLowerCase());
			if (user == null) {
				return null;
			}

			int iterations = 10000;
			int keyLength = 512;
			char[] passwordChars = password.toCharArray();

			String dbHash = user.getPasswordHash().substring(0, keyLength / 4);
			String salt = user.getPasswordHash().substring(keyLength / 4);
			byte[] saltBytes = UserDAO.hexStringToByteArray(salt);

			byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
			String hashedString = Hex.encodeHexString(hashedBytes);

			user.setPasswordHash(null);

			if (!hashedString.equalsIgnoreCase(dbHash)) {
				return null;
			}

			conn.setAutoCommit(false);

			SecureRandom random = new SecureRandom();
			byte tokenBytes[] = new byte[64];
			random.nextBytes(tokenBytes);
			String tokenString = Hex.encodeHexString(tokenBytes);

			LocalDateTime loginDate = LocalDateTime.now();
			LocalDateTime expirationDate = null;
			if (user.getRoleId() == 1) {
				expirationDate = LocalDateTime.now().plusHours(3);
			} else if (user.getRoleId() == 2) {
				expirationDate = LocalDateTime.now().plusDays(5);
			}

			int rs = updateToken(conn, userName, tokenString, loginDate, expirationDate);
			conn.commit();

			user.setToken(tokenString);
			user.setExpirationDate(expirationDate);

			return user;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Login function called by LoginServlet (POST Request),
	 * Checks if the created user already exists,
	 * If not, create user and add to database
	 * @param user
	 * @param password
	 * @return
	 */
	public static int createUser(User user, String password) {
		try (Connection conn = DBConnect.getConnection()) {
			boolean userExist = checkUserExistance(conn, user.getUserName());

			if (userExist) {
				return -2;
			}

			SecureRandom random = new SecureRandom();
			byte saltBytes[] = new byte[64];
			random.nextBytes(saltBytes);

			String salt = Hex.encodeHexString(saltBytes);
			int iterations = 10000;
			int keyLength = 512;
			char[] passwordChars = password.toCharArray();

			byte[] hashedBytes = UserDAO.hashPassword(passwordChars, saltBytes, iterations, keyLength);
			String hashedPassword = Hex.encodeHexString(hashedBytes);
			hashedPassword = hashedPassword + salt;

			conn.setAutoCommit(false);
			int rs = createUser(conn, user, hashedPassword);
			conn.commit();
			conn.close();
			return rs;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;
	}
}