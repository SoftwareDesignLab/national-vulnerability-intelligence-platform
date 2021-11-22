/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.utils;

import com.opencsv.CSVWriter;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * This class exports each table in a given SQLite to CSV files database
 * 
 * @author axoeec
 *
 */
public class SqliteHelper {
	private final String TAG = SqliteHelper.class.getSimpleName();
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private String createBackupFileName(String tableName) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd_HHmm");
		return "output/" + tableName + "_" + sdf.format(new Date()) + ".csv";
	}

	/**
	 * Connect to an SQLite database at <fullSqliteDbPath>
	 * 
	 * @param fullSqliteDbPath
	 * @return
	 */
	private Connection connect(String fullSqliteDbPath) {
		// SQLite connection string
		String url = "jdbc:sqlite:" + fullSqliteDbPath;
		Connection conn = null;
		try {
			conn = DriverManager.getConnection(url);
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		return conn;
	}

	/**
	 * Export the SQLite database at <fullSqliteDbPath> to CSV files
	 * 
	 * @param fullSqliteDbPath
	 */
	public void exportSqliteDatabase(String fullSqliteDbPath) {
		CSVWriter csvWrite = null;
		Connection conn = null;
		Statement stmt = null;
		ResultSet rs = null;

		try {
			conn = this.connect(fullSqliteDbPath);
			stmt = conn.createStatement();

			// get table names
			String[] types = { "TABLE" };
			DatabaseMetaData md = conn.getMetaData();
			rs = md.getTables(null, null, "%", types);
			ArrayList<String> tables = new ArrayList<>();
			while (rs.next()) {
				tables.add(rs.getString("TABLE_NAME"));
			}

			for (String table : tables) {

				// init csvWriter
				String fileName = createBackupFileName(table);
				csvWrite = new CSVWriter(new FileWriter(fileName));

				// get table metadata
				rs = stmt.executeQuery("SELECT * FROM " + table);
				ResultSetMetaData rsmd = rs.getMetaData();
				int columnCount = rsmd.getColumnCount();

				// write columns
				String[] columnArr = new String[columnCount];
				// The column count starts from 1
				for (int i = 1; i <= columnCount; i++) {
					columnArr[i - 1] = rsmd.getColumnName(i);
				}
				csvWrite.writeNext(columnArr);

				// loop through the result set
				while (rs.next()) {
					columnArr = new String[columnCount];
					for (int i = 1; i <= columnCount; i++) {
						columnArr[i - 1] = rs.getString(i).trim();
					}
					csvWrite.writeNext(columnArr);
				}
			}

		} catch (Exception e) {
			logger.error(e.toString());
		} finally {
			try {
				csvWrite.close();
			} catch (IOException e) {
				/* ignored */
			}

			try {
				rs.close();
			} catch (SQLException e) {
				/* ignored */
			}

			try {
				conn.close();
			} catch (SQLException e) {
				/* ignored */
			}

		}
	}

}