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
package data;

import java.sql.*;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DBConnect {
	private static Logger logger = LogManager.getLogger(DBConnect.class);

	public static void main(String[] args) throws SQLException {
		try(Connection conn = getConnection();
			Statement stmt = conn.createStatement()
		) {
			ResultSet rs = stmt.executeQuery("SHOW TABLES;");
			ResultSetMetaData rsmd = rs.getMetaData();
			int columnsNumber = rsmd.getColumnCount();
			logger.info("Number of Columns: " + columnsNumber);
			while (rs.next()) {
				StringBuilder rowInfo = new StringBuilder();
				for (int i = 1; i <= columnsNumber; i++) {
					if (i > 1) rowInfo.append(",  ");
					String columnValue = rs.getString(i);
					rowInfo.append(columnValue).append(" ").append(rsmd.getColumnName(i));
				}
				logger.info(rowInfo);
			}
			rs.close();
		}
	}

	public static Connection getConnection() throws SQLException {
		try {
			Class.forName("com.mysql.cj.jdbc.Driver");
		} catch (ClassNotFoundException e) {
			throw new RuntimeException(e);
		}

		Connection conn = getConnectionFromEnvironment();

		if(conn == null) {
			conn = getConnectionFromContext();
		}

		if(conn == null) {
			throw new NullPointerException("Unable to create connection from Environment: " + System.getenv("JDBC_CONNECTION_STRING"));
		}

		return conn;
	}

	private static Connection getConnectionFromContext() {
		Connection conn = null;
		try {
			Context ctx = new InitialContext();
			DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/nvip_db_mysql");
			ctx.close();
			conn = ds.getConnection();
		} catch (NamingException ex) {
			logger.error("Unable to create DataSource from Context");
			logger.error(ex.getMessage());
		} catch (SQLException ex) {
			logger.error("Username or Password for NVIP database is incorrect, please check context.xml to correct --> " + ex.toString());
			logger.error(ex.getMessage());
		}
		return conn;
	}

	/**
	 * Retrieves and builds a connection from an environment or system property named JDBC_CONNECTION_STRING
	 *
	 * @return
	 */
	private static Connection getConnectionFromEnvironment() throws NullPointerException {
		Connection conn;

		String jdbcConnString = System.getenv("JDBC_CONNECTION_STRING");

		if (jdbcConnString == null) {
			// checks to see if the envvar is set as a system property
			jdbcConnString = System.getProperty("JDBC_CONNECTION_STRING");
		}

		try {
			conn = DriverManager.getConnection(jdbcConnString);
		} catch (SQLException ex) {
			logger.error("Username or Password for NVIP database is incorrect, please check context.xml to correct --> " + ex.toString());
			logger.error(ex.getMessage());
			throw new NullPointerException(ex.getMessage());
		}
		return conn;
	}

	public static String getDatabaseType() {
		return "MySQL";
	}
}
