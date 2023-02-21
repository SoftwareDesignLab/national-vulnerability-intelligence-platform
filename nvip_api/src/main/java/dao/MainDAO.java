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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import data.DBConnect;

public class MainDAO {
	private static String dbType = DBConnect.getDatabaseType();
	private static final String[] MAIN_PAGE_COUNTS = { "CvesAdded", "CvesUpdated", "not_in_nvd_count",
			"not_in_mitre_count", "run_date_times", "avgTimeGapNvd", "avgTimeGapMitre" };
	private static Logger logger = LogManager.getLogger(MainDAO.class);

	public static Map<String, String> getMainPageCounts() {

		if (dbType == "MySQL") {
			try (Connection conn = DBConnect.getConnection()) {

				Map<String, String> mainPageCounts = new HashMap<>();

				String query = "SELECT group_concat(drh.not_in_mitre_count SEPARATOR ';') not_in_mitre, "
						+ " group_concat(drh.not_in_nvd_count SEPARATOR ';') not_in_nvd,  group_concat(drh.run_date_time SEPARATOR ';') run_date_time, "
						+ " group_concat(drh.avg_time_gap_nvd SEPARATOR ';') avg_time_gap_nvd, group_concat(drh.avg_time_gap_mitre SEPARATOR ';') avg_time_gap_mitre, "
						+ " group_concat(drh.added_cve_count SEPARATOR ';') added_cve_count, group_concat(drh.updated_cve_count SEPARATOR ';') updated_cve_count"
						+ " FROM (SELECT run_date_time, not_in_nvd_count, not_in_mitre_count, avg_time_gap_nvd, avg_time_gap_mitre, added_cve_count, updated_cve_count "
						+ " FROM dailyrunhistory ORDER BY run_date_time DESC LIMIT 15) AS drh;";

				PreparedStatement stmt = conn.prepareStatement(query);

				ResultSet rs = stmt.executeQuery(query);

				if (rs.next()) {
					mainPageCounts.put(MAIN_PAGE_COUNTS[0], rs.getString("added_cve_count") + "");
					mainPageCounts.put(MAIN_PAGE_COUNTS[1], rs.getString("updated_cve_count") + "");
					mainPageCounts.put(MAIN_PAGE_COUNTS[2], rs.getString("not_in_nvd"));
					mainPageCounts.put(MAIN_PAGE_COUNTS[3], rs.getString("not_in_mitre"));
					mainPageCounts.put(MAIN_PAGE_COUNTS[4], rs.getString("run_date_time"));
					mainPageCounts.put(MAIN_PAGE_COUNTS[5], rs.getString("avg_time_gap_nvd"));
					mainPageCounts.put(MAIN_PAGE_COUNTS[6], rs.getString("avg_time_gap_mitre"));
				}

				conn.close();

				return mainPageCounts;
			} catch (SQLException e) {
				logger.error(e.toString());
				e.printStackTrace();
			}
		}

		return null;
	}
}