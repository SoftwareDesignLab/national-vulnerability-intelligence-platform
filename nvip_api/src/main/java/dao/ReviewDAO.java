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
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import data.DBConnect;
import model.CVSSupdate;
import model.CvssScore;
import model.Product;
import model.VDOgroup;
import model.VDOupdateInfo;
import model.VdoCharacteristic;
import model.Vulnerability;
import model.VulnerabilityDetails;
import model.VulnerabilityDomain;
import model.VulnerabilityForReviewList;
import util.VulnerabilityUtil;

public class ReviewDAO {
	private static String dbType = DBConnect.getDatabaseType();
	private final static int defaultLimit = 10000;
	private static Logger logger = LogManager.getLogger(ReviewDAO.class);

	/**
	 * Get search results from a Review page search query
	 * @param searchDate
	 * @param crawled
	 * @param rejected
	 * @param accepted
	 * @param reviewed
	 * @return
	 */
	public static List<VulnerabilityForReviewList> getSearchResults(LocalDate searchDate, boolean crawled, boolean rejected, boolean accepted, boolean reviewed) {
		
		String query = "SELECT v.vuln_id, v.cve_id, v.platform, v.last_modified_date, v.exists_at_nvd, v.exists_at_mitre, v.status_id, drh.run_date_time "
				+ "from vulnerability as v inner join vulnerabilityupdate as vu on v.vuln_id=vu.vuln_id " + "inner join dailyrunhistory as drh on vu.run_id = drh.run_id "
				+ "where drh.run_date_time BETWEEN ? AND ? and (";

		if (!crawled && !rejected && !accepted && !reviewed) {
			return null;
		}
		boolean orStatement = false;
		if (crawled) {
			query = query + "(v.status_id = 1 or v.status_id is null)";
			orStatement = true;
		}

		if (rejected) {
			if (orStatement) {
				query = query + " or ";
			}
			query = query + "v.status_id = 2";
			orStatement = true;
		}

		if (reviewed) {
			if (orStatement) {
				query = query + " or ";
			}

			query = query + "v.status_id = 3";
			orStatement = true;
		}

		if (accepted) {
			if (orStatement) {
				query = query + " or ";
			}

			query = query + "v.status_id = 4";
		}

		query = query + ");";
		
		try (Connection conn = DBConnect.getConnection();
				PreparedStatement stmt = conn.prepareStatement(query)) {

			// Get the CVEs for the last 3 days from 2 days ago to today (inclusive)
			LocalDateTime today = LocalDateTime.of(searchDate, LocalTime.MIDNIGHT);

			List<VulnerabilityForReviewList> dailyVulns = new ArrayList<VulnerabilityForReviewList>();

			stmt.setTimestamp(1, Timestamp.valueOf(today));
			stmt.setTimestamp(2, Timestamp.valueOf(today.plusDays(1)));

			ResultSet rs = stmt.executeQuery();

			while (rs.next()) {
				String vuln_id = rs.getString("vuln_id");
				String cve_id = rs.getString("cve_id");
				String status_id = rs.getString("status_id");
				String run_date_time = rs.getString("run_date_time");
				dailyVulns.add(new VulnerabilityForReviewList(vuln_id, cve_id, status_id, null, run_date_time));

			}
			rs.close();
			return dailyVulns;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * TODO: Refactor this to use GROUP CONCAT for VDO Labels and products
	 * Obtains details of a specific vulnerability
	 * @param cveID
	 * @return
	 */
	public static VulnerabilityDetails getVulnerabilityDetails(String cveID) {
		try (Connection conn = DBConnect.getConnection();
				PreparedStatement stmt = conn.prepareStatement(
						"SELECT v.vuln_id, v.cve_id, v.description, p.product_id, p.domain, p.cpe, ar.release_date, ar.version, vng.vdo_noun_group_id, vng.vdo_noun_group_name, vl.vdo_label_id, vl.vdo_label_name, vc.vdo_confidence, "
								+ "cs.cvss_severity_id, cs.cvss_severity_class, c.impact_score, v.status_id, u.first_name, u.last_name, u.user_name, uvu.user_id, uvu.update_date, drh.run_date_time "
								+ "FROM vulnerability v "
								+ "LEFT JOIN affectedrelease ar ON ar.cve_id = v.cve_id "
								+ "LEFT JOIN product p ON p.product_id = ar.product_id "
								+ "LEFT JOIN (SELECT user_id, cve_id, max(datetime) AS update_date FROM uservulnerabilityupdate GROUP BY user_id, cve_id) uvu ON v.cve_id = uvu.cve_id "
								+ "LEFT JOIN user u ON u.user_id = uvu.user_id "
								+ "LEFT JOIN vdocharacteristic AS vc ON vc.cve_id = v.cve_id "
								+ "LEFT JOIN vdonoungroup AS vng ON vng.vdo_noun_group_id = vc.vdo_noun_group_id "
								+ "LEFT JOIN vdolabel AS vl ON vl.vdo_label_id = vc.vdo_label_id "
								+ "LEFT JOIN cvssscore AS c ON v.cve_id = c.cve_id "
								+ "LEFT JOIN cvssseverity AS cs ON cs.cvss_severity_id = c.cvss_severity_id "
								+ "LEFT JOIN vulnerabilityupdate AS vu ON vu.vuln_id = v.vuln_id "
								+ "LEFT JOIN dailyrunhistory AS drh ON drh.run_id = vu.run_id "
								+ "WHERE v.cve_id = ?")) {

			VulnerabilityDetails vulnDetails = null;

			stmt.setString(1, cveID);
			ResultSet rs = stmt.executeQuery();

			while (rs.next()) {

				if (vulnDetails == null) {
					String vuln_id = rs.getString("vuln_id");
					String cve_id = rs.getString("cve_id");
					String status_id = rs.getString("status_id");
					String description = rs.getString("description");
					String cvss_severity_class = rs.getString("cvss_severity_class");
					String impact_score = rs.getString("impact_score");
					String first_name = rs.getString("first_name");
					String last_name = rs.getString("last_name");
					String user_id = rs.getString("user_id");
					String user_name = rs.getString("user_name");
					String update_date = rs.getString("update_date");
					String run_date_time = rs.getString("run_date_time");

					vulnDetails = new VulnerabilityDetails(vuln_id, cve_id, description, status_id, cvss_severity_class, impact_score, first_name, last_name, user_name, user_id, update_date, run_date_time);
				}

				String vdo_noun_group_name = rs.getString("vdo_noun_group_name");
				String vdo_label_name = rs.getString("vdo_label_name");
				String vdo_confidence = rs.getString("vdo_confidence");

				if (vulnDetails.getVdoGroups().containsKey(vdo_noun_group_name)) {
					vulnDetails.getVdoGroups().get(vdo_noun_group_name).getVdoLabel().put(vdo_label_name, vdo_confidence);
				} else {
					vulnDetails.getVdoGroups().put(vdo_noun_group_name, new VDOgroup(vdo_noun_group_name, vdo_label_name, vdo_confidence));
				}

				String domain = rs.getString("domain");
				String cpe = rs.getString("cpe");
				String version = rs.getString("version");
				String product_id = rs.getString("product_id");

				if (domain != null || cpe != null) {
					vulnDetails.getVulnDomain().add(new VulnerabilityDomain(product_id, domain, cpe, version));
				}
			}

			rs.close();

			return vulnDetails;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Updates Daily Vulnerability
	 * @param dateRange
	 * @return
	 */
	public static int updateDailyVulnerability(int dateRange) {
		try (Connection conn = DBConnect.getConnection();
				CallableStatement stmt = conn.prepareCall("CALL prepareDailyVulnerabilities(?, ?, ?)")) {

			LocalDateTime today = LocalDateTime.of(LocalDate.now(), LocalTime.MIDNIGHT).plusDays(1);

			stmt.setTimestamp(1, Timestamp.valueOf(today.minusDays(dateRange)));
			stmt.setTimestamp(2, Timestamp.valueOf(today));

			stmt.registerOutParameter("cveCount", Types.INTEGER);

			stmt.execute();

			return stmt.getInt("cveCount");

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;

	}

	/**
	 * Adds manual update log to uservulnerabilityupdate table to keep track
	 * of manual updates to vulnerabilities
	 * @param status_id
	 * @param vuln_id
	 * @param user_id
	 * @param cve_id
	 * @param info
	 * @return
	 */
	public static int atomicUpdateVulnerability(int status_id, int vuln_id, int user_id, String cve_id, String info) {
		try (Connection conn = DBConnect.getConnection()) {

			conn.setAutoCommit(false);

			int rs = atomicUpdateVulnerability(conn, status_id, vuln_id, user_id, cve_id, info);
			conn.commit();
			return rs;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;

	}

	/**
	 * Updates description of a vulnerability in vulnerabilities table
	 * @param conn
	 * @param description
	 * @param vuln_id
	 * @return
	 */
	public static int updateVulnerabilityDescription(Connection conn, String description, int vuln_id) {
		try(PreparedStatement stmt = conn.prepareStatement("UPDATE vulnerability SET description = ? WHERE vuln_id=?")) {

			stmt.setString(1, description);
			stmt.setInt(2, vuln_id);
			int rs = stmt.executeUpdate();

			return rs;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;

	}

	/**
	 * Helper function for atomicUpdateVulnerability,
	 * provides database connection and runs query to update uservulnerabilityupdate
	 * table
	 * @param conn
	 * @param status_id
	 * @param vuln_id
	 * @param user_id
	 * @param cve_id
	 * @param info
	 * @return
	 */
	public static int atomicUpdateVulnerability(Connection conn, int status_id, int vuln_id, int user_id, String cve_id, String info) {
		
		try (PreparedStatement stmt1 = conn.prepareStatement("UPDATE vulnerability SET last_modified_date= ?, status_id = ? WHERE vuln_id = ?;");
				PreparedStatement stmt2 = conn.prepareStatement("INSERT INTO nvip.uservulnerabilityupdate (user_id, cve_id, datetime, info) VALUES (?, ?, ?, ?)")) {

			LocalDateTime today = LocalDateTime.now();

			stmt1.setTimestamp(1, Timestamp.valueOf(today));
			stmt1.setInt(2, status_id);
			stmt1.setInt(3, vuln_id);

			int rs = stmt1.executeUpdate();

			stmt2.setInt(1, user_id);
			stmt2.setString(2, cve_id);
			stmt2.setTimestamp(3, Timestamp.valueOf(today));
			stmt2.setString(4, info);

			rs = stmt2.executeUpdate();

			return rs;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;

	}

	/**
	 * Updates the CVSS of a given Vulnerability
	 * @param conn
	 * @param cvssUpdate
	 * @param cve_id
	 * @return
	 */
	public static int updateVulnerabilityCVSS(Connection conn, CVSSupdate cvssUpdate, String cve_id) {
		try(PreparedStatement stmt1 = conn.prepareStatement("DELETE FROM CvssScore WHERE cve_id = ?");
				PreparedStatement stmt2 = conn.prepareStatement("INSERT INTO CvssScore (cve_id, cvss_severity_id, severity_confidence, impact_score, impact_confidence) VALUES (?,?,?,?,?)")) {
			
			stmt1.setString(1, cve_id);
			int rs = stmt1.executeUpdate();

			stmt2.setString(1, cve_id);
			stmt2.setInt(2, cvssUpdate.getCvss_severity_id());
			stmt2.setDouble(3, cvssUpdate.getSeverity_confidence());
			stmt2.setDouble(4, cvssUpdate.getImpact_score());
			stmt2.setDouble(5, cvssUpdate.getImpact_confidence());
			rs = stmt2.executeUpdate();

			return rs;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;

	}

	/**
	 * Deletes entries from VdoCharacteristic table by CVE-ID
	 * and replaces them with new entries from vdoUpdate parameter
	 * @param conn - MYSQL Connection
	 * @param vdoUpdate - Contains an Arraylist of VDOupdateInfo objects that obtains
	 * the new information to be inserted into VdoCharacteristic
	 * @param cve_id - ID of CVE that needs to have VDO updated
	 * @return
	 */
	public static int updateVulnerabilityVDO(Connection conn, VDOupdateInfo vdoUpdate, String cve_id) {
		try (PreparedStatement stmt1 = conn.prepareStatement("DELETE FROM VdoCharacteristic WHERE cve_id = ?");
				PreparedStatement stmt2 = conn.prepareStatement("INSERT INTO VdoCharacteristic (cve_id, vdo_label_id,vdo_confidence,vdo_noun_group_id) VALUES (?,?,?,?)")){

			stmt1.setString(1, cve_id);
			int rs = stmt1.executeUpdate();

			for (int i = 0; i < vdoUpdate.getVdoRecords().size(); i++) {
				stmt2.setString(1, cve_id);
				stmt2.setInt(2, vdoUpdate.getVdoRecords().get(i).getLabelID());
				stmt2.setDouble(3, vdoUpdate.getVdoRecords().get(i).getConfidence());
				stmt2.setInt(4, vdoUpdate.getVdoRecords().get(i).getGroupID());
				rs = stmt2.executeUpdate();
			}

			return rs;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;

	}

	/**
	 * Deletes provided affectedRelease entries
	 * Will loop through all productsIDs and delete entries with the same
	 * productID and CVE-ID
	 * 
	 * @param conn - Connection to database
	 * @param productsID - Array of product IDs to be deleted from AffectedRelease Table
	 * @param cve_id - cve_id to be deleted from AffectedRelease table
	 * @return 
	 * 
	 */
	public static int removeProductsFromVulnerability(Connection conn, int[] productsID, String cve_id) {
		try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM AffectedRelease where product_id = ?  AND cve_id = ?") ){

			int rs = 0;

			for (int i = 0; i < productsID.length; i++) {
				stmt.setInt(1, productsID[i]);
				stmt.setString(2, cve_id);
				rs = stmt.executeUpdate();
			}

			return rs;

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;

	}

	/**
	 * Runs a full update on Vulnerabilities tables as per request from
	 * ReviewServlet
	 * @param updateDescription - Checks if description needs to be updated
	 * @param updateVDO - Checks if VDO needs to be updated
	 * @param updateCVSS - Checks if CVSS needs to be updated
	 * @param updateAffRel - Checks if Affected Releases table needs to be updated
	 * @param status_id
	 * @param vuln_id
	 * @param user_id
	 * @param cve_id
	 * @param updateInfo - Info on update (For atomic update logs)
	 * @param cveDescription - New CVE Description
	 * @param vdoUpdate - New VDO Info
	 * @param cvssUpdate - New CVSS Info
	 * @param productsToRemove - Products to remove from Affected Releases
	 * @return -1
	 */
	public static int complexUpdate(boolean updateDescription, boolean updateVDO, boolean updateCVSS, boolean updateAffRel, int status_id, int vuln_id, int user_id, String cve_id, String updateInfo,
			String cveDescription, VDOupdateInfo vdoUpdate, CVSSupdate cvssUpdate, int[] productsToRemove) {

		try(Connection conn = DBConnect.getConnection()) {
			conn.setAutoCommit(false);

			int rs = 0;

			if (updateDescription) {
				rs = updateVulnerabilityDescription(conn, cveDescription, vuln_id);
			}

			if (updateVDO) {
				rs = updateVulnerabilityVDO(conn, vdoUpdate, cve_id);
			}

			if (updateCVSS) {
				rs = updateVulnerabilityCVSS(conn, cvssUpdate, cve_id);
			}

			if (updateAffRel) {
				rs = removeProductsFromVulnerability(conn, productsToRemove, cve_id);
			}

			rs = atomicUpdateVulnerability(conn, status_id, vuln_id, user_id, cve_id, updateInfo);

			conn.commit();

		} catch (SQLException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}

		return -1;

	}

}