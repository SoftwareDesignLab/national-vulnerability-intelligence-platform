package edu.rit.se.nvip.db;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.CompositeVulnerability.CveReconcileStatus;
import edu.rit.se.nvip.model.DailyRun;
import edu.rit.se.nvip.model.Vulnerability;
import edu.rit.se.nvip.model.VulnerabilityAttribsForUpdate;
import edu.rit.se.nvip.utils.UtilHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

// NOTE this is informal testing of the DatabaseHelper class. Should be revised for proper unit testing
public class DatabaseHelperTest {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	@Test
	public void testTimeDiff() {
		Date createdDateTime = null;
		Date lastModifiedDateTime = null;
		try {
			createdDateTime = UtilHelper.longDateFormat.parse("2020/05/10 12:32:00");
			lastModifiedDateTime = UtilHelper.longDateFormat.parse("2020/05/10 18:32:00");
		} catch (Exception e) {
		}
		int hours = (int) ChronoUnit.HOURS.between(createdDateTime.toInstant(), lastModifiedDateTime.toInstant());
		assertEquals(true, (hours == 6));
	}

	@Test
	public void testDailyRun() {
		// DatabaseHelper databaseHelper = new DatabaseHelper();
		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();
		DailyRun dailyRun = new DailyRun("2020/05/10 21:48:00", 5, 100, 5, 4, 3, 1, 6, 0);
		assertEquals(true, (databaseHelper.insertDailyRun(dailyRun) > 0));
		databaseHelper.deleteDailyRun(dailyRun.getRunDateTime()); // now delete the record!
	}

//	@Test
//	public void testDbInsert() {
//		List<CompositeVulnerability> vulnList = new ArrayList<CompositeVulnerability>();
//		CompositeVulnerability vuln = new CompositeVulnerability(0, "url1", "CXX-XXXX-111", "versio1", null, UtilHelper.longDateFormat.format(new Date()), "Content1", null);
//		vulnList.add(vuln);
//
//		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();
//
//		// get temp run id
//		DailyRun dailyRun = new DailyRun("2020/05/10 21:48:00", 5, 100, 5, 4, 3, 1, 6, 0);
//		databaseHelper.insertDailyRun(dailyRun);
//		int runId = databaseHelper.getMaxRunId();
//
//		boolean done = databaseHelper.insertVuln(vulnList, runId);
//		assertEquals(true, done);
//
//		// delete inserted test CVE
//		databaseHelper.deleteVulnSource(vuln.getCveId());
//		databaseHelper.deleteVulnerabilityUpdate(runId);
//		databaseHelper.deleteVuln(vuln.getCveId());
//
//		// delete temp run id
//		databaseHelper.deleteDailyRun(dailyRun.getRunDateTime()); // now delete the record!
//	}
//
//	@Test
//	public void tesDBPerformance() {
//
//		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();
//		List<CompositeVulnerability> vulnList = new ArrayList<CompositeVulnerability>();
//		long start = System.currentTimeMillis();
//
//		for (int i = 0; i < 1000; i++) {
//			CompositeVulnerability vuln = new CompositeVulnerability(0, "url" + i, "CXX-XXXX-1" + i, "versio" + i, null, UtilHelper.longDateFormat.format(new Date()), "Content" + i, null);
//			vulnList.add(vuln);
//		}
//
//		// get a temp run id
//		// int runId = 1;
//		DailyRun dailyRun = new DailyRun("2020/05/10 21:48:00", 5, 100, 5, 4, 3, 1, 6, 0);
//		int runId = databaseHelper.insertDailyRun(dailyRun);
//		logger.info("Created a temporay run Id {} for db tests..", runId);
//
//		databaseHelper.insertVuln(vulnList, runId);
//		long end = System.currentTimeMillis();
//		logger.info("DB insert time for " + vulnList.size() + " vulns: " + ((end - start)) + " mseconds!");
//		assertEquals(true, ((end - start) < 30000));
//
//		logger.info("Testing vuln updates...");
//
//		start = System.currentTimeMillis();
//		Connection conn = null;
//		try {
//			Map<String, VulnerabilityAttribsForUpdate> existingVulnMap = databaseHelper.getExistingVulnerabilities(); // use static map!
//			conn = databaseHelper.getConnection();
//
//			// update vuln content
//			for (int i = 0; i < vulnList.size(); i++) {
//				CompositeVulnerability vuln = vulnList.get(i);
//				vuln.setCveReconcileStatus(CveReconcileStatus.UPDATE);
//				vulnList.set(i, vuln);
//			}
//
//			int count = 0;
//			for (CompositeVulnerability vuln : vulnList) {
//				databaseHelper.updateVuln(vuln, conn, existingVulnMap, runId);
//				count++;
//				if (count % 100 == 0)
//					logger.info("Updated {} items", count);
//			}
//		} catch (SQLException e) {
//			e.printStackTrace();
//		} finally {
//			try {
//				conn.close();
//			} catch (SQLException e) {
//
//			}
//		}
//		end = System.currentTimeMillis();
//		logger.info("DB update time for " + vulnList.size() + " vulns: " + ((end - start)) + " mseconds!");
//		assertEquals(true, ((end - start) < 30000));
//
//		start = System.currentTimeMillis();
//		databaseHelper.deleteVulnerabilityUpdate(runId);
//		for (CompositeVulnerability vuln : vulnList) {
//			databaseHelper.deleteVulnSource(vuln.getCveId());
//			databaseHelper.deleteVuln(vuln.getCveId());
//		}
//		end = System.currentTimeMillis();
//		logger.info("DB delete time for " + vulnList.size() + " vulns: " + ((end - start)) + " mseconds!");
//
//		// delete temporary run id created
//		databaseHelper.deleteDailyRun(dailyRun.getRunDateTime()); // now delete the record!
//
//		assertEquals(true, ((end - start) < 10000));
//	}

	@Test
	public void testProductIDFromCPE() {
		DatabaseHelper db = DatabaseHelper.getInstance();
		int expectedId = -1;
		int id = db.getProdIdFromCpe("DOES_NOT_EXIST");
		assertEquals(expectedId, id);

		id = db.getProdIdFromCpe("cpe:2.3:a:openbsd:openssh:7.2:-:*:*:*:*:*:*");
		assertTrue(id >= -1);
	}

	@Test
	public void testTimeGapCalculation() {
		DatabaseHelper db = DatabaseHelper.getInstance();
		try (Connection connection = db.getConnection();) {
			Map<String, Vulnerability> existingVulnMap = db.getExistingVulnerabilities();

			// create a vuln list for test
			List<CompositeVulnerability> vulnList = new ArrayList<>();
			String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());
			String description = "An attacker can cause a Denial of Service and kernel panic in v4.2 and earlier versions of Espressif esp32 via a malformed beacon csa frame. The device requires a reboot to recover.";
			CompositeVulnerability vuln = new CompositeVulnerability(0, "", "CVE-2021-34173", null, null, lastModifiedDate, description, null);
			vulnList.add(vuln);

			int[] counts = db.checkNvdMitreStatusForCrawledVulnerabilityList(connection, vulnList, existingVulnMap);
			logger.info("Out of {} CVEs, {} are existing, {} are new. Found {} time gaps", vulnList.size(), counts[0], counts[1], counts[2]);

			// existingCveCount, newCveCount, foundTimeGapCount
			boolean done = (counts[0] + counts[1]) == vulnList.size();
			assertEquals(done, true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
