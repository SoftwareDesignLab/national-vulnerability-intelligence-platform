package edu.rit.se.nvip.utils;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.utils.email.EmailDailyCveList;

public class PrepareDataForWebUi {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public static void main(String[] args) {
		PrepareDataForWebUi prepareVulnerabilityDataForWebUi = new PrepareDataForWebUi();
		prepareVulnerabilityDataForWebUi.prepareDataforWebUi();

	}

	/**
	 * Generate a summary table that will be used by the Web UI.
	 */
	public void prepareDataforWebUi() {
		LocalDateTime today = LocalDateTime.now();
		String sql = "DELETE FROM nvip.vulnerabilityaggregate WHERE description like '%** RESERVED ** This candidate%' or description like '%\"** REJECT **  DO NOT%';";
		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();

		try (Connection conn = databaseHelper.getConnection(); CallableStatement stmt = conn.prepareCall("CALL prepareDailyVulnerabilities(?, ?, ?)"); Statement stmt2 = conn.prepareStatement(sql);) {

			stmt.setTimestamp(1, Timestamp.valueOf(today.minusHours(168))); // 7 days
			stmt.setTimestamp(2, Timestamp.valueOf(today));

			stmt.registerOutParameter(3, java.sql.Types.INTEGER);

			stmt.execute();
			int count = stmt.getInt(3);

			// remove reserved and rejected CVES for which a description is not found!
			int count2 = stmt2.executeUpdate(sql);

			logger.info("Prepared {} CVEs for Web UI, {} Reserved/Rejected CVEs ignnored.", count - count2, count2);

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
