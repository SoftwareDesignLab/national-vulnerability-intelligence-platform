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
			stmt.setTimestamp(2, Timestamp.valueOf(today));

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
