/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
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

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.utils.email.EmailDailyCveList;

public class PrepareDataForWebUi {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * Generate a summary table that will be used by the Web UI.
	 */
	public void prepareDataforWebUi() {
		LocalDateTime today = LocalDateTime.now();
		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();

		try (
				Connection conn = databaseHelper.getConnection();
				CallableStatement stmt = conn.prepareCall("CALL prepareDailyVulnerabilities(?, ?, ?)");
		) {

			stmt.setTimestamp(1, Timestamp.valueOf(today.minusHours(168))); // 7 days
			stmt.setTimestamp(2, Timestamp.valueOf(today.plusHours(24)));

			stmt.registerOutParameter(3, java.sql.Types.INTEGER);

			stmt.execute();
			int count = stmt.getInt(3);

			logger.info("Prepared {} CVEs for Web UI", count);

			// send CVE notifactions
			try {
				EmailDailyCveList emailDailyCveList = new EmailDailyCveList();
				emailDailyCveList.sendCveNotificationEmailToSystemAdmin();
			} catch (Exception e1) {
				logger.error("Error sending CVE notification to admins! {}", e1);
			}

		} catch (Exception e) {
			logger.error(e.toString());
		}
	}

}
