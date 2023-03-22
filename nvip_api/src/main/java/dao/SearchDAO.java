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
package dao;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import data.DBConnect;
import model.CvssScore;
import model.Product;
import model.VdoCharacteristic;
import model.Vulnerability;
import util.VulnerabilityUtil;

public class SearchDAO {
	private static final Logger logger = LogManager.getLogger(SearchDAO.class);
	private static String dbType = DBConnect.getDatabaseType();
	private final static int defaultLimit = 10000;

	/**
	 * Parses the information retrieved from the Search Form initialization query
	 * and splits the returned strings into arrays.
	 * 
	 * @param infoType   Type of form info that is being returned (i.e. CVSS Scores,
	 *                   VDO labels)
	 * @param infoArrStr Delimited string containing all the values needed to
	 *                   initialize the Search Form for the given info type
	 * @return Map with the info type as the key and an array containing all the
	 *         entities for the given info type
	 */
	private static HashMap<String, String[]> parseSearchInfo(String infoType, String infoArrStr) {
		HashMap<String, String[]> infoMap = new HashMap<>();

		if (infoType == "cvssScores") {
			infoMap.put(infoType, infoArrStr.split(";"));
		} else if (infoType == "vdoNounGroups") {
			String[] vdoEntities = infoArrStr.split("\\|");

			for (String vdoEntity : vdoEntities) {
				String[] vdo = vdoEntity.split(":");
				infoMap.put(vdo[0], vdo[1].split(";"));
			}
		}

		return infoMap;
	}

	/**
	 * Calls a stored procedure containing labels for parameters that can be
	 * searched in the search form (i.e. VDO Noun Groups, VDO Labels, CVSS Score
	 * labels, etc.)
	 * 
	 * @return Map containing parameter name of labels (i.e. CVSS Scores) and the
	 *         label strings
	 */
	public static Map<String, Map<String, String[]>> getSearchInfo() {
		try (Connection conn = DBConnect.getConnection()) {
			Map<String, Map<String, String[]>> searchMap = new HashMap<>();

			CallableStatement stmt = conn.prepareCall("CALL getSearchFormInfo()");

			ResultSet rs = stmt.executeQuery();

			while (rs.next()) {

				searchMap = Stream
						.of(new String[][] { { "cvssScores", rs.getString("cvss_scores") },
								{ "vdoNounGroups", rs.getString("vdo_noun_groups") } })
						.collect(Collectors.toMap(data -> data[0], data -> parseSearchInfo(data[0], data[1])));
			}

			return searchMap;
		} catch (SQLException e) {
			logger.error(e.toString());
		}

		return null;
	}

	/**
	 * Conducts a query to search for a specific CVE by it's ID within the database
	 * 
	 * @param cve_id
	 * @return
	 * @throws SQLException
	 */
	public static Map<Integer, List<Vulnerability>> getSearchResultsByID(String cve_id) {
		Timestamp fixedDate = null;
		String[] sources = {};
		VdoCharacteristic[] vdoList = {};
		CvssScore[] cvssScoreList = null;
		Product[] products = null;
		List<Vulnerability> searchResults = new ArrayList<>();
		HashMap<Integer, List<Vulnerability>> searchResultMap = new HashMap<Integer, List<Vulnerability>>();

		try (Connection conn = DBConnect.getConnection()) {

			String query = "Select v.vuln_id, v.cve_id, v.description, v.platform, v.published_date, v.exists_at_mitre, v.exists_at_nvd, v.last_modified_date,"
					+ " ar.version, p.product_id, p.cpe, p.domain, group_concat(vc.vdo_confidence SEPARATOR ';') AS vdo_label_confidences, "
					+ " group_concat(vl.vdo_label_name SEPARATOR ';') AS vdo_labels, group_concat(vn.vdo_noun_group_name SEPARATOR ';') AS vdo_noun_groups,"
					+ " cvsever.cvss_severity_class as base_severity, cvscore.severity_confidence, cvscore.impact_score, cvscore.impact_confidence, group_concat(vc.vdo_label_id SEPARATOR ';') AS label_ids, ex.publisher_url"
					+ " FROM vulnerability v" + " LEFT JOIN affectedrelease ar ON ar.cve_id = v.cve_id"
					+ " LEFT JOIN product p ON p.product_id = ar.product_id"
					+ " LEFT JOIN exploit ex ON ex.vuln_id = v.vuln_id"
					+ " LEFT JOIN vdocharacteristic vc ON vc.cve_id = v.cve_id"
					+ " LEFT JOIN vdolabel vl ON vl.vdo_label_id = vc.vdo_label_id"
					+ " LEFT JOIN vdonoungroup vn ON vn.vdo_noun_group_id = vl.vdo_noun_group_id"
					+ " LEFT JOIN cvssscore cvscore ON cvscore.cve_id = v.cve_id"
					+ " LEFT JOIN cvssseverity cvsever ON cvsever.cvss_severity_id = cvscore.cvss_severity_id"
					+ " WHERE v.cve_id = '" + cve_id + "'"
					+ "GROUP BY v.vuln_id, v.cve_id, v.description, v.platform, v.published_date, v.exists_at_mitre, v.exists_at_nvd, v.last_modified_date, ar.version, p.product_id, p.cpe, p.domain, cvsever.cvss_severity_class, cvscore.severity_confidence, cvscore.impact_score, cvscore.impact_confidence, ex.publisher_url";

			System.out.println(query);
			PreparedStatement stmt = conn.prepareStatement(query);

			ResultSet rs = stmt.executeQuery(query);

			if (rs.next()) {

				vdoList = VulnerabilityUtil.parseVDOList(rs.getString("cve_id"), rs.getString("vdo_labels"),
						rs.getString("vdo_label_confidences"), rs.getString("vdo_noun_groups"));
				cvssScoreList = VulnerabilityUtil.parseCvssScoreList(rs.getString("cve_id"),
						rs.getString("base_severity"), rs.getString("severity_confidence"),
						rs.getString("impact_score"), rs.getString("impact_confidence"));
				products = VulnerabilityUtil.parseProductList(rs.getString("product_id"), rs.getString("cpe"),
						rs.getString("domain"), rs.getString("version"));

				searchResults.add(new Vulnerability(rs.getInt("vuln_id"), rs.getString("cve_id"),
						rs.getString("description"), rs.getString("platform"), rs.getString("published_date"),
						rs.getString("last_modified_date"), (fixedDate == null ? null : fixedDate.toLocalDateTime()),
						rs.getBoolean("exists_at_mitre"), rs.getBoolean("exists_at_nvd"), sources, vdoList,
						cvssScoreList, products));

			}
			conn.close();
			searchResultMap.put(1, searchResults);
			return searchResultMap;

		} catch (SQLException e) {
			logger.error(e.toString());
		}
		return null;

	}

	/**
	 * Calls a stored procedure to obtain vulnerabilities that match the parameters
	 * passed in. Returns the set of vulnerabilities ordered by earliest update.
	 * through the search form.
	 * 
	 * @param vulnId        - Vulnerability id. Used to define range of results
	 *                      (above or below given id)
	 * @param keyword       - Keyword that is within the vulnerability description
	 * @param startDate     - Starting date for last update of the vulnerabilities
	 * @param endDate       - End date for last update of the vulnerabilities
	 * @param cvssScores    - Set of CVSS scores values which the vulnerabilities
	 *                      must contain (at least one)
	 * @param vdoNounGroups - Set of VDO Noun Groups which the vulnerabilities must
	 *                      contain (at least one)
	 * @param vdoLabels     - Set of VDO labels which the vulnerabilities must
	 *                      contain (at least one)
	 * @param inMitre       - Parameter which indicates vulnerability has an entry
	 *                      on MITRE
	 * @param inNvd         - Parameter which indicates vulnerability has an entry
	 *                      on NVD
	 * @param limitCount    - Sets the limit of vulnerabilities returned. Defaults
	 *                      to the set default if not provided
	 * @param isBefore      - Defines if search range before or after given id
	 * @return Map of a list of vulnerabilities to the total count of those
	 *         vulnerabilities
	 */
	public static Map<Integer, List<Vulnerability>> getSearchResults(int vulnId, String keyword, LocalDate startDate,
			LocalDate endDate, String[] cvssScores, String[] vdoLabels, int limitCount, String product) {

		try (Connection conn = DBConnect.getConnection()) {
			Timestamp fixedDate = null;
			String[] sources = {};
			VdoCharacteristic[] vdoList = {};
			CvssScore[] cvssScoreList = null;
			Product[] products = null;
			// Product product = null; // Temporary product until update Vuln entity to
			// handle multiple products
			List<Vulnerability> searchResults = new ArrayList<>();
			int totalCount = 0;

			HashMap<Integer, List<Vulnerability>> searchResultMap = new HashMap<Integer, List<Vulnerability>>();

			String query = "Select v.vuln_id, v.cve_id, v.description, v.platform, v.published_date, v.exists_at_mitre, v.exists_at_nvd, v.last_modified_date,"
					+ " ar.version, p.product_id, p.cpe, p.domain, group_concat(vc.vdo_confidence SEPARATOR ';') AS vdo_label_confidences, "
					+ " group_concat(vl.vdo_label_name SEPARATOR ';') AS vdo_labels, group_concat(vn.vdo_noun_group_name SEPARATOR ';') AS vdo_noun_groups,"
					+ " cvsever.cvss_severity_class as base_severity, cvscore.severity_confidence, cvscore.impact_score, cvscore.impact_confidence, group_concat(vc.vdo_label_id SEPARATOR ';') AS label_ids, ex.publisher_url"
					+ " FROM vulnerability v" + " LEFT JOIN affectedrelease ar ON ar.cve_id = v.cve_id"
					+ " LEFT JOIN product p ON p.product_id = ar.product_id"
					+ " LEFT JOIN exploit ex ON ex.vuln_id = v.vuln_id"
					+ " LEFT JOIN vdocharacteristic vc ON vc.cve_id = v.cve_id"
					+ " LEFT JOIN vdolabel vl ON vl.vdo_label_id = vc.vdo_label_id"
					+ " LEFT JOIN vdonoungroup vn ON vn.vdo_noun_group_id = vl.vdo_noun_group_id"
					+ " LEFT JOIN cvssscore cvscore ON cvscore.cve_id = v.cve_id"
					+ " LEFT JOIN cvssseverity cvsever ON cvsever.cvss_severity_id = cvscore.cvss_severity_id";

			if (startDate != null || endDate != null) {
				query += " LEFT JOIN vulnerabilityupdate vup ON vup.vuln_id = v.vuln_id"
						+ " LEFT JOIN dailyrunhistory drh ON drh.run_id = vup.run_id";
			}

			query += " WHERE v.description like '%" + keyword + "%'";

			if (startDate != null) {
				query += " AND drh.run_date_time >= '" + startDate + "'";
			}

			if (endDate != null) {
				query += " AND drh.run_date_time <= '" + endDate + "'";
			}

			if (cvssScores != null) {

				// Boolean that separates added query strings from whether or not
				// the CVSSScore is first in the array
				boolean cvssCheck = true;

				for (String cvssScore : cvssScores) {

					if (cvssCheck) {
						query += " AND (cvss_severity_class = '" + cvssScore + "'";
					} else {
						query += " OR cvss_severity_class = '" + cvssScore + "'";
					}

					cvssCheck = false;
				}

				query += " )";

			}

			if (product != null) {
				query += " AND (p.cpe LIKE '%" + product + "%' OR p.domain LIKE '%" + product + "%')";
			}

			query += "GROUP BY v.vuln_id, ar.version, p.product_id, base_severity, cvscore.severity_confidence, cvscore.impact_score, cvscore.impact_confidence, ex.publisher_url";

			if (vdoLabels != null) {

				// check to see if AND claus needs to be added to query string
				boolean vdoCheck = false;

				query += " HAVING";
				for (String vdoLabel : vdoLabels) {

					if (vdoCheck)
						query += " AND";

					// Additional check for Physical label, in case of search for Physical Security,
					// etc.
					if (vdoLabel.equals("Physical")) {
						query += " label_ids LIKE '%27%'";
					} else {
						query += " vdo_labels LIKE '%" + vdoLabel + "%'";
					}

					vdoCheck = true;
				}
			}

			query += " ORDER BY v.exists_at_nvd ASC, v.vuln_id DESC LIMIT " + limitCount + ";";

			// TODO Figure out where/how we can pass these parameters in through the ui
			// Maybe change these to booleans, currently have the parameters passed
			// but not correctly though

			/*
			 * if (inMitre != null ) { if (inMitre.equals("true")) { query +=
			 * " AND exists_at_mitre = 0"; } else { query += " AND exists_at_mitre = 1"; } }
			 * 
			 * if (inNvd != null) { System.out.println(inNvd); if (inNvd.equals("true")) {
			 * query += " AND exists_at_nvd = 0"; } else { query +=
			 * " AND exists_at_nvd = 1"; } }
			 */

			System.out.println(query);
			PreparedStatement stmt = conn.prepareStatement(query);

			ResultSet rs = stmt.executeQuery(query);

			while (rs.next()) {
				vdoList = VulnerabilityUtil.parseVDOList(rs.getString("cve_id"), rs.getString("vdo_labels"),
						rs.getString("vdo_label_confidences"), rs.getString("vdo_noun_groups"));
				cvssScoreList = VulnerabilityUtil.parseCvssScoreList(rs.getString("cve_id"),
						rs.getString("base_severity"), rs.getString("severity_confidence"),
						rs.getString("impact_score"), rs.getString("impact_confidence"));
				products = VulnerabilityUtil.parseProductList(rs.getString("product_id"), rs.getString("cpe"),
						rs.getString("domain"), rs.getString("version"));

				// Temporary product until update Vuln entity to handle multiple products
				// product = products.length > 0 ? products[0] : null;

				searchResults.add(new Vulnerability(rs.getInt("vuln_id"), rs.getString("cve_id"),
						rs.getString("description"), rs.getString("platform"), rs.getString("published_date"),
						rs.getString("last_modified_date"), (fixedDate == null ? null : fixedDate.toLocalDateTime()),
						rs.getBoolean("exists_at_mitre"), rs.getBoolean("exists_at_nvd"), sources, vdoList,
						cvssScoreList, products));

				totalCount++;
			}

			conn.close();

			searchResultMap.put(totalCount, searchResults);
			return searchResultMap;
		} catch (SQLException e) {
			logger.error(e.toString());
		}

		return null;
	}

	public static void main(String[] args) {

	}
}