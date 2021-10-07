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
package edu.rit.se.nvip.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import edu.rit.se.nvip.model.*;
import edu.rit.se.nvip.utils.CveUtils;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;
import java.sql.*;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.*;

/**
 * 
 * The DatabaseHelper class is used to insert and update vulnerabilities found
 * from the webcrawler/processor to a sqlite database
 */
public class DatabaseHelper {
	protected NumberFormat formatter = new DecimalFormat("#0.00000");
	private HikariConfig config = null;
	private HikariDataSource dataSource;
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	String databaseType = "mysql";

	/**
	 * Database needs its own date formats for concurrent execution.
	 */
	private DateFormat longDateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
	private DateFormat longDateFormatMySQL = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	/**
	 * SQL sentences. Please include the INSERT/UPDATE/DELETE SQL sentences of each
	 * entity in this section!
	 */
	private String insertVulnSql = "INSERT INTO Vulnerability (cve_id, description, platform, introduced_date, published_date, created_date, last_modified_date, "
			+ "fixed_date, exists_at_nvd, exists_at_mitre, time_gap_nvd, time_gap_mitre) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);";
	private String insertVulnDescriptionSql = "INSERT INTO Vulnerability (cve_id, description) VALUES (?,?);";
	private String updateVulnSql = "UPDATE Vulnerability SET description = ?," + "platform = ?," + "introduced_date = ?," + "published_date = ?," + "last_modified_date = ?,"
			+ "fixed_date = ? WHERE (cve_id = ?);";
	private String updateVulnDescriptionSql = "UPDATE Vulnerability SET description = ? WHERE cve_id = ?;";

	private String updateVulnSqlNvd = "UPDATE Vulnerability SET exists_at_nvd = ?, time_gap_nvd = ? WHERE cve_id = ?;";
	private String updateVulnSqlMitre = "UPDATE Vulnerability SET exists_at_mitre = ?, time_gap_mitre = ? WHERE cve_id = ?;";
	private String selectVulnSql = "SELECT * FROM Vulnerability;";
	private String deleteVulnSql = "DELETE FROM Vulnerability WHERE cve_id=?;";

	private String insertVulnSourceSql = "INSERT INTO VulnSourceUrl (cve_id, url) VALUES (?,?);";
	private String selectVulnSourceSql = "SELECT * FROM VulnSourceUrl;";
	private String deleteVulnSourceSql = "DELETE FROM VulnSourceUrl WHERE cve_id=?;";

	private String insertNvipSourceSql = "INSERT INTO NvipSourceUrl (url, description, http_status) VALUES (?,?,?);";
	private String updateNvipSourceSql = "UPDATE NvipSourceUrl SET http_status = ? WHERE (url = ?);";
	private String deleteNvipSourceSql = "DELETE FROM NvipSourceUrl WHERE url = ?;";
	private String deleteAllNvipSourceSql = "DELETE FROM NvipSourceUrl;";
	private String selectAllNvipSourceSql = "SELECT * FROM NvipSourceUrl;";
	private String selectNvipSourceSql = "SELECT count(*) FROM NvipSourceUrl WHERE (url = ?);";

	private String insertCveActualSql = "INSERT INTO CVEActual (cve_id, full_page_url, processed_date, cve_content) VALUES (?,?,?,?);";
	private String updateCveActualSql = "UPDATE CVEActual SET processed_date = ?, cve_content = ? WHERE (cve_id = ? AND full_page_url = ?);";
	private String selectCveActualSql = "SELECT * FROM CVEActual;";

	private String insertCveHistorySql = "INSERT INTO CVEHistory (cve_id, full_page_url, processed_date, cve_content) VALUES (?,?,?,?);";
	private String updateCveHistorySql = "UPDATE CVEHistory SET cve_content = ? WHERE (cve_id = ? AND full_page_url = ? AND processed_date = ?);";
	private String selectCveHistorySql = "SELECT * FROM CveHistory;";

	private String insertDailyRunSql = "INSERT INTO DailyRunHistory (run_date_time, crawl_time_min, total_cve_count, not_in_nvd_count, not_in_mitre_count,"
			+ "not_in_both_count, new_cve_count, added_cve_count, updated_cve_count) VALUES (?,?,?,?,?,?,?,?,?);";
	private String updateDailyRunSql = "UPDATE DailyRunHistory SET crawl_time_min = ?, db_time_min = ?, total_cve_count = ?, not_in_nvd_count = ?, "
			+ "not_in_mitre_count = ?, not_in_both_count = ?, new_cve_count = ?, avg_time_gap_nvd = ?, avg_time_gap_mitre = ? WHERE (run_id = ?);";
	private String selectDailyRunSql = "SELECT * FROM DailyRunHistory;";
	private String deleteDailyRunSql = "DELETE FROM DailyRunHistory WHERE run_date_time=?;";

	private String insertVdoCharacteristicSql = "INSERT INTO VdoCharacteristic (cve_id, vdo_label_id,vdo_confidence,vdo_noun_group_id) VALUES (?,?,?,?);";
	private String deleteVdoCharacteristicSql = "DELETE FROM VdoCharacteristic WHERE cve_id=?;";

	private String insertCvssScoreSql = "INSERT INTO CvssScore (cve_id, cvss_severity_id, severity_confidence, impact_score, impact_confidence) VALUES (?,?,?,?,?);";
	private String deleteCvssScoreSql = "DELETE FROM CvssScore WHERE cve_id=?;";

	private String selectCvssSeveritySql = "SELECT * FROM cvssseverity;";

	private String insertProductSql = "INSERT INTO Product (CPE, domain) VALUES (?, ?);";
	private String deleteProductSql = "DELETE FROM Product WHERE CPE=?;";
	private String getProductCountFromCpeSql = "SELECT count(*) from Product where cpe = ?";
	private String getProductFromCpeSql = "SELECT * from Product where cpe = ?";
	private String getCpeFromDomainSql = "SELECT p.product_id FROM Product p where p.Domain like \"%?%\" order by p.cpe";
	private String productTableSelectAllSql = "SELECT * FROM product";
	private String getIdFromCpe = "SELECT * FROM nvip.product where cpe = ?;";

	private String insertAffectedReleaseSql = "INSERT INTO AffectedRelease (cve_id, product_id, release_date, version) VALUES (?, ?, ?, ?);";
	private String updateAffectedReleaseSql = "update AffectedRelease set release_date = ?, version = ? where cve_id = ? and product_id = ?;";
	private String deleteAffectedReleaseSql = "DELETE FROM AffectedRelease where cve_id = ?;";

	private String insertVulnerabilityUpdateSql = "INSERT INTO VulnerabilityUpdate (vuln_id, column_name, column_value, run_id) VALUES (?,?,?,?);";
	private String deleteVulnerabilityUpdateSql = "DELETE FROM VulnerabilityUpdate WHERE run_id=?;";
	private String selectVulnerabilityIdSql = "SELECT vuln_id FROM nvip.vulnerability WHERE cve_id = ?";

	private String selectVdoLabelSql = "SELECT * FROM vdolabel;";
	private String selectVdoNounGroupSql = "SELECT * FROM vdonoungroup;";

	private String insertExploitSql = "INSERT INTO Exploit (vuln_id, cve_id, publisher_id, publish_date, publisher_url, description, exploit_code, nvip_record_date) VALUES (?,?,?,?,?,?,?,?);";
	private String deleteExploitSql = "DELETE FROM Exploit WHERE vuln_id=?;";

	private static DatabaseHelper databaseHelper = null;
	private static Map<String, VulnerabilityAttribsForUpdate> existingVulnMap = new HashMap<String, VulnerabilityAttribsForUpdate>();

	/**
	 * Thread safe singleton implementation
	 * 
	 * @return
	 */
	public static synchronized DatabaseHelper getInstance() {
		if (databaseHelper == null)
			databaseHelper = new DatabaseHelper();

		return databaseHelper;
	}

	/**
	 * The private constructor sets up HikariCP for connection pooling. Singleton
	 * DP!
	 */
	private DatabaseHelper() {
		try {
			MyProperties propertiesNvip = new MyProperties();
			propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
			databaseType = propertiesNvip.getDatabaseType();
			logger.info("New NVIP.DatabaseHelper instantiated! It is configured to use " + databaseType + " database!");
			if (databaseType.equalsIgnoreCase("mysql"))
				Class.forName("com.mysql.cj.jdbc.Driver");

		} catch (ClassNotFoundException e2) {
			logger.error("Error while loading database type from the nvip.properties! " + e2.toString());
		}

		String configFile = "db-" + databaseType + ".properties";
		try {

			ClassLoader loader = Thread.currentThread().getContextClassLoader();
			Properties props = new Properties();
			try (InputStream resourceStream = loader.getResourceAsStream(configFile)) {
				props.load(resourceStream);
			}
			config = new HikariConfig(props);
			config.setMaximumPoolSize(50);
		} catch (Exception e1) {
			logger.warn("Could not load db.properties(" + configFile + ") from src/main/resources! Looking at the root path now!");
			config = new HikariConfig("db-" + databaseType + ".properties"); // in the production system get it from the
																				// root dir
		}

		dataSource = new HikariDataSource(config); // init data source

	}

	/**
	 * Retrieves the connection from the DataSource (HikariCP)
	 * 
	 * @return the connection pooling connection
	 * @throws SQLException
	 */
	public Connection getConnection() throws SQLException {
		return dataSource.getConnection();
	}

	public boolean testDbConnection() {
		try {
			Connection conn = dataSource.getConnection();
			if (conn != null) {
				conn.close();
				return true;
			} else
				return false;
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		return false;
	}

	/**
	 * Creates a table titled using the createTableStatement SQL statement in the
	 * database. Takes in the HikariCP connection as a parameter.
	 * 
	 * @param conn
	 * @param createTableStatement
	 * @throws SQLException
	 */
	private void createTable(Connection conn, String createTableStatement) throws SQLException {
		Statement stmt = conn.createStatement();
		stmt.execute(createTableStatement);
	}

	/**
	 * Checks if the tableName table exists in the database. Takes in the HikariCP
	 * connection as a parameter.
	 * 
	 * @param conn
	 * @param tableName
	 * @return
	 * @throws SQLException
	 */
	private boolean checkTableExist(Connection conn, String tableName) throws SQLException {
		try (ResultSet rs = conn.getMetaData().getTables(null, null, tableName, null)) {
			while (rs.next()) {
				String table = rs.getString("TABLE_NAME");
				if (table != null && table.equalsIgnoreCase(tableName)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Helper function to convert a bool to an int for database storage. 0 is false,
	 * 1 is true.
	 * 
	 * @param bool The bool to be converted to int
	 * @return The int that was converted
	 */
	private int convertBoolToInt(boolean bool) {
		if (bool) {
			return 1;
		} else {
			return 0;
		}
	}

	/**
	 * Helper function to convert an int to a bool when retrieved from the database.
	 * 0 is false, 1 is true.
	 * 
	 * @param num The int to be converted to a bool
	 * @return The bool that was converted
	 */
	private boolean convertIntToBool(int num) {
		if (num == 1) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * used to insert a list of CPE products into the database
	 *
	 * @param products List of product objects
	 * @return Number of inserted products, <0 if error.
	 */
	public int insertCpeProducts(Collection<Product> products) {
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(insertProductSql); PreparedStatement getCount = conn.prepareStatement(getProductCountFromCpeSql);) {
			int count = 0;
			int total = products.size();
			for (Product product : products) {
				getCount.setString(1, product.getCpe());
				ResultSet res = getCount.executeQuery();
				if (res.next() && res.getInt(1) != 0) {
					continue; // product already exists, skip!
				}
				pstmt.setString(1, product.getCpe());
				pstmt.setString(2, product.getDomain());
				pstmt.executeUpdate();
				count++;
			}

			logger.info("\rInserted: " + count + " of " + total + " products to DB! Skipped: " + (total - count) + " existing ones!");
			return count;
		} catch (SQLException e) {
			logger.error(e.getMessage());
			return -1;
		}
	}

	/**
	 * gets all products from database and puts them in a map with format <CPE, DOM>
	 *
	 * @return map of Domain to CPE strings
	 */
	public Map<String, String> getProductMap() {
		Connection conn = null;
		Map<String, String> products = new HashMap<>();
		try {
			conn = getConnection();
			PreparedStatement pstmt = conn.prepareStatement(productTableSelectAllSql);
			ResultSet res = pstmt.executeQuery();
			while (res.next()) {
				String cpe = res.getString("Cpe");
				String dom = res.getString("Domain");
				products.put(cpe, dom);
			}
		} catch (SQLException e) {

		} finally {
			try {
				conn.close();
			} catch (SQLException e) {
			}
		}
		return products;
	}

	/**
	 * add list of products to the database uses only one connection
	 *
	 * @param products list of products
	 */
	public void addProductsToDatabase(Collection<Product> products) {
		Connection conn = null;
		try {
			conn = getConnection();

			for (Product p : products) {
				insertProduct(p, conn);
			}
		} catch (SQLException e) {

		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}
	}

	/**
	 * inserts single product into database will not insert duplicates
	 * 
	 * @param product
	 * @return
	 */
	public Boolean insertProduct(Product product, Connection conn) {
		try {
			PreparedStatement pstmt = conn.prepareStatement(insertProductSql);

			PreparedStatement getCount = conn.prepareStatement(getProductCountFromCpeSql);
			getCount.setString(1, product.getCpe());
			ResultSet res = getCount.executeQuery();
			if (res.next() && res.getInt(1) != 0) {
				return true;
			}
			pstmt.setString(1, product.getCpe());
			pstmt.setString(2, product.getDomain());
			pstmt.executeUpdate();

			logger.info("Inserted product: " + product.getDomain());
			return true;
		} catch (SQLException e) {
			logger.error(e.getMessage());
			return false;
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}
	}

	/**
	 * gets a product ID from database based on CPE
	 *
	 * @param cpe CPE string of product
	 * @return product ID if product exists in database, -1 otherwise
	 */
	public int getProdIdFromCpe(String cpe) {
		int result;
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(getIdFromCpe);) {
			pstmt.setString(1, cpe);
			ResultSet res = pstmt.executeQuery();
			if (res.next())
				result = res.getInt("product_id");
			else
				result = -1;
		} catch (SQLException e) {
			logger.error(e.getMessage());
			result = -2;
		}
		return result;
	}

	public int getProdIdFromCpe(Product product) {
		return getProdIdFromCpe(product.getCpe());
	}

	/**
	 * updates the affected release table with a list of affected releases
	 * 
	 * @param affectedReleases list of affected release objects
	 */
	public void insertAffectedReleasesV2(List<AffectedRelease> affectedReleases) {
		logger.info("Inserting {} affected releases...", affectedReleases.size());
		int count = 0;
		try (Connection conn = getConnection(); Statement stmt = conn.createStatement(); PreparedStatement pstmt = conn.prepareStatement(insertAffectedReleaseSql);) {
			for (AffectedRelease affectedRelease : affectedReleases) {
				try {
					int prodId = getProdIdFromCpe(affectedRelease.getCpe());
					pstmt.setString(1, affectedRelease.getCveId());
					pstmt.setInt(2, prodId);
					pstmt.setString(3, affectedRelease.getReleaseDate());
					pstmt.setString(4, affectedRelease.getVersion());
					count += pstmt.executeUpdate();
				} catch (Exception e) {
					logger.error("Could not add affected release for Cve: {} Related Cpe: {}, Error: {}", affectedRelease.getCveId(), affectedRelease.getCpe(), e.toString());
				}
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		logger.info("Done. Inserted {} affected releases into the database!", count);
	}

	/**
	 * delete affected releases for given CVEs
	 * 
	 * @param affectedReleases
	 */
	public void deleteAffectedReleases(List<AffectedRelease> affectedReleases) {
		logger.info("Deleting existing affected releases in database for {} items..", affectedReleases.size());
		try (Connection conn = getConnection(); Statement stmt = conn.createStatement(); PreparedStatement pstmt = conn.prepareStatement(deleteAffectedReleaseSql);) {
			for (AffectedRelease affectedRelease : affectedReleases) {
				pstmt.setString(1, affectedRelease.getCveId());
				pstmt.executeUpdate();
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		logger.info("Done. Deleted existing affected releases in database!");
	}

	/**
	 * Get mapping between products-CVEs
	 * 
	 * @param conn
	 * @return
	 */
	public Map<Integer, List<String>> getProductCveMapFromDb() {
		String selectSql = "SELECT * FROM AffectedRelease";
		Map<Integer, List<String>> map = new HashMap<>();
		try (Connection conn = getConnection(); Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(selectSql);) {
			while (rs.next()) {
				int prodId = rs.getInt("product_id");
				if (map.containsKey(prodId)) {
					map.get(prodId).add(rs.getString("cve_id"));
				} else {
					List<String> cves = new ArrayList<>();
					cves.add(rs.getString("cve_id"));
					map.put(prodId, cves);
				}
			}
		} catch (Exception e) {
			logger.error(e.toString());
		}
		return map;
	}

	/**
	 * Get existing vulnerabilities hash map. This method was added to improve
	 * DatabaseHelper, NOT to query each CVEID during a CVE update! Existing
	 * vulnerabilities are read only once, and this hash map is queried during
	 * individual update operations!
	 * 
	 * @return
	 */
	public Map<String, VulnerabilityAttribsForUpdate> getExistingVulnerabilities() {

		if (existingVulnMap.size() == 0) {
			synchronized (DatabaseHelper.class) {
				if (existingVulnMap.size() == 0) {
					int vulnId = 0;
					String cveId, description, createdDate;
					boolean existAtNvd, existAtMitre;
					existingVulnMap = new HashMap<String, VulnerabilityAttribsForUpdate>();
					Connection connection = null;

					try {
						connection = getConnection();

						String selectSql = "SELECT vuln_id, cve_id, description, created_date, exists_at_nvd, exists_at_mitre from Vulnerability";
						PreparedStatement pstmt = connection.prepareStatement(selectSql);
						ResultSet rs = pstmt.executeQuery();

						while (rs.next()) {
							vulnId = rs.getInt("vuln_id");
							cveId = rs.getString("cve_id");
							description = rs.getString("description");
							createdDate = rs.getString("created_date");
							existAtNvd = convertIntToBool(rs.getInt("exists_at_nvd"));
							existAtMitre = convertIntToBool(rs.getInt("exists_at_mitre"));
							VulnerabilityAttribsForUpdate existingVulnInfo = new VulnerabilityAttribsForUpdate(vulnId, cveId, description, existAtNvd, existAtMitre, createdDate);
							existingVulnMap.put(cveId, existingVulnInfo);
						}
						logger.info("NVIP has loaded " + existingVulnMap.size() + " existing CVE items from DB!");
					} catch (Exception e) {
						logger.error("Error while getting existing vulnerabilities from DB: Exception: " + e.toString());
						logger.error("This is a serious error! NVIP will not be able to decide whether to insert or update! Exiting...");
						System.exit(1);
					} finally {
						try {
							connection.close();
						} catch (SQLException ignored) {

						}
					}
				} // if (existingVulnMap.size() == 0) {
			} // synchronized (DatabaseHelper.class) {
		} // if (existingVulnMap.size() == 0) {
		else {
			// logger.info("NVIP has loaded " + existingVulnMap.size() + " existing CVE
			// items from memory!");
		}

		return existingVulnMap;
	}

	/**
	 * Takes in a list of vulnerabilities (vulnList) and inserts each into the
	 * Vulnerability table in the database. If the CveId exists in the Vulnerability
	 * table already, then the updateVuln function is called.
	 * 
	 * @param vulnList List of Vulnerability objects to be inserted
	 * @return true if successfully inserted, false if an exception occurred.
	 */
	public boolean recordVulnerabilityList(List<CompositeVulnerability> vulnList, int runId) {
		/**
		 * load existing vulnerabilities. this is supposed to be done once for during
		 * each run! Using a static map, to make sure each thread does not call this
		 * separately!
		 */
		existingVulnMap = getExistingVulnerabilities();
		try (Connection connection = getConnection();) {
			// connection.setAutoCommit(false); // commit at the end!
			int insertCount = 0, updateCount = 0, noChangeCount = 0;
			for (int i = 0; i < vulnList.size(); i++) {
				CompositeVulnerability vuln = vulnList.get(i);

				if (i % 100 == 0 && i > 0)
					logger.info("Updated/inserted/notchanged {}/{}/{} of {} vulnerabilities", updateCount, insertCount, noChangeCount, vulnList.size());

				try {
					if (existingVulnMap.containsKey(vuln.getCveId())) {
						int count = updateVulnerability(vuln, connection, existingVulnMap, runId);
						if (count > 0)
							updateCount++;
						else
							noChangeCount++;

						continue;
					}

					try (PreparedStatement pstmt = connection.prepareStatement(insertVulnSql);) {

						pstmt.setString(1, vuln.getCveId());
						pstmt.setString(2, vuln.getDescription());
						pstmt.setString(3, vuln.getPlatform());
						pstmt.setString(4, vuln.getIntroduceDate());
						pstmt.setString(5, vuln.getPublishDate());
						// pstmt.setString(6, vuln.getCreateDate());
						pstmt.setString(6, vuln.getLastModifiedDate()); // during insert create date is last modified
																		// date
						pstmt.setString(7, vuln.getLastModifiedDate());
						pstmt.setString(8, vuln.getFixDate());
						/**
						 * Bug fix: indexes 9 and 10 were wrong
						 */
						pstmt.setInt(9, convertBoolToInt(vuln.existInNvd()));
						pstmt.setInt(10, convertBoolToInt(vuln.existInMitre()));
						pstmt.setInt(11, vuln.getTimeGapNvd());
						pstmt.setInt(12, vuln.getTimeGapMitre());
						pstmt.executeUpdate();
					} catch (Exception e) {
						logger.error(e.toString());
						continue; // if you have an error here, skip the rest!
					}

					/**
					 * insert sources
					 */
					insertVulnSource(vuln.getVulnSourceList(), connection);

					/**
					 * insert VDO
					 */
					insertVdoCharacteristic(vuln.getVdoCharacteristicInfo(), connection);

					/**
					 * insert CVSS
					 */
					insertCvssScore(vuln.getCvssScoreInfo(), connection);

					/**
					 * insert Affected Releases. This process has been moved toa later stage!
					 */
					// insertAffectedReleases(vuln.getAffectedReleases());

					/**
					 * record updates
					 */
					List<Integer> vulnIdList = getVulnerabilityIdList(vuln.getCveId());
					for (Integer vulnId : vulnIdList)
						insertVulnerabilityUpdate(vulnId, "description", "New CVE: " + vuln.getCveId(), runId);

					insertCount++;
				} catch (Exception e) {
					logger.error(e.toString());
				}

			} // for loop

			int total = updateCount + insertCount + noChangeCount;
			logger.info("DatabaseHelper updated/inserted/notchanged " + total + " [" + updateCount + "/" + insertCount + "/" + noChangeCount + "] of " + vulnList.size() + " vulnerabilities.");
			// connection.commit();

			// do time gap analysis
			recordTimeGapsOfCrawledVulnerabilitiesForNvdMitre(connection, vulnList, existingVulnMap);

		} catch (Exception e) {
			logger.error(e.getMessage());
			return false;
		}
		return true;
	}

	/**
	 * Updates the Vulnerability table with the Vulnerability object (vuln) passed
	 * in.
	 * 
	 * @param vuln            Vulnerability object to be updated in database
	 * @param connection      HikariCP connection to database
	 * @param existingVulnMap list of exiting vulnerabilities
	 * @throws SQLException
	 */
	public int updateVulnerability(CompositeVulnerability vuln, Connection connection, Map<String, VulnerabilityAttribsForUpdate> existingVulnMap, int runId) throws SQLException {

		VulnerabilityAttribsForUpdate existingAttribs = existingVulnMap.get(vuln.getCveId());
		// checkTimeGaps(vuln, connection, existingAttribs); // check time gaps!

		// check reconcile status, is an update needed?
		if (vuln.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE)
			return 0; // if no need to update then return

		try (PreparedStatement pstmt = connection.prepareStatement(updateVulnSql);) {
			// update vulnerability

			pstmt.setString(1, vuln.getDescription());
			pstmt.setString(2, vuln.getPlatform());
			pstmt.setString(3, vuln.getIntroduceDate());
			pstmt.setString(4, vuln.getPublishDate());
			/**
			 * Bug fix: do not reset create date during update! Update last modified date
			 * ONLY!
			 */
			// pstmt.setString(5, vuln.getCreateDate());
			pstmt.setString(5, vuln.getLastModifiedDate());
			pstmt.setString(6, vuln.getFixDate());
			pstmt.setString(7, vuln.getCveId()); // WHERE clause in SQL statement

			pstmt.executeUpdate();
		} catch (SQLException e1) {
			// you may still continue updating other vuln attribs below!
			logger.error("Error while updating Vuln: {} Exception: {}", vuln, e1);

		}

		// update affected releases. This process moved to a later stage!
		// updateAffectedReleases(vuln.getAffectedReleases());

		/**
		 * update sources
		 */
		deleteVulnSource(vuln.getCveId(), connection); // clear existing ones
		insertVulnSource(vuln.getVulnSourceList(), connection); // add them

		/**
		 * update vdo
		 */
		updateVdoLabels(vuln.getCveId(), vuln.getVdoCharacteristicInfo(), connection);

		/**
		 * update cvss scores
		 */
		deleteCvssScore(vuln.getCveId(), connection); // clear existing ones
		insertCvssScore(vuln.getCvssScoreInfo(), connection); // add them

		/**
		 * record updates if there is an existing vuln
		 */
		if (existingAttribs != null)
			insertVulnerabilityUpdate(existingAttribs.getVulnId(), "description", existingAttribs.getDescription(), runId);

		return 1; // done
	} // updateVuln

	/**
	 * insert a vulnerability column value
	 * 
	 * @param vulnId
	 * @param columnName
	 * @param columnValue
	 * @param runId
	 * @return
	 */
	public boolean insertVulnerabilityUpdate(int vulnId, String columnName, String columnValue, int runId) {
		Connection conn = null;
		PreparedStatement pstmt = null;
		try {
			conn = getConnection();
			pstmt = conn.prepareStatement(insertVulnerabilityUpdateSql);
			pstmt.setInt(1, vulnId);
			pstmt.setString(2, columnName);
			pstmt.setString(3, columnValue);
			pstmt.setInt(4, runId);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error("Error while logging vuln updates! " + e.getMessage() + "\n" + pstmt.toString());
			return false;
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {
			}
		}
		return true;
	}

	/**
	 * This method calculates the time gaps of a CVE for NVD and MITRE if any. A
	 * time gap for NVD/MITRE is defined as the number of hours between the time a
	 * vulnerability is found by NVIP and the time it is added to NVD/MITRE. Note
	 * that the time gaps calculated here will not be precise, because they will be
	 * depending on the time that NVIP is run. However, they will give an idea about
	 * the value provided by NVIP in terms of EARLY detection of vulnerabilities.
	 * 
	 * 
	 * To calculate a time gap certain conditions must be met:
	 * 
	 * (1) CVE has a created date in the database: existingAttribs.getCreatedDate()
	 * != null (We must know when the CVE was first added to db, to calculate a time
	 * gap)
	 * 
	 * (2) ((!vulnAlreadyInNvd && vuln.existInNvd()) || (!vulnAlreaadyInMitre &&
	 * vuln.existInMitre())): The CVE did not exist in nvd/mitre before, but it is
	 * there now!
	 * 
	 * (3) !CveUtils.isCveReservedEtc(vuln): The CVE must NOT be reserved/rejected
	 * etc.
	 * 
	 * @param vuln
	 * @param connection
	 * @param existingAttribs
	 */
	private boolean checkTimeGapsForCVE(CompositeVulnerability vuln, Connection connection, VulnerabilityAttribsForUpdate existingAttribs) {
		boolean timeGapFound = false;
		PreparedStatement pstmt = null;
		boolean vulnAlreadyInNvd = existingAttribs.isExistAtNvd();
		boolean vulnAlreaadyInMitre = existingAttribs.isExistAtMitre();

		if ((existingAttribs.getCreatedDate() != null) && ((!vulnAlreadyInNvd && vuln.existInNvd()) || (!vulnAlreaadyInMitre && vuln.existInMitre()))
				&& !CveUtils.isCveReservedEtc(vuln.getDescription())) {

			Date createdDateTime = null;
			Date lastModifiedDateTime = null;
			try {

				/**
				 * We are not expecting a time gap more than 1 year. If CVE is from prior years
				 * skip time gap check
				 */
				String[] cveParts = vuln.getCveId().split("-");
				int cveYear = Integer.parseInt(cveParts[1]);
				int currentYear = Calendar.getInstance().get(Calendar.YEAR);
				boolean calculateGap = (cveYear == currentYear);
				if (!calculateGap)
					return false;

				if (databaseType.equalsIgnoreCase("mysql"))
					createdDateTime = longDateFormatMySQL.parse(existingAttribs.getCreatedDate());
				else
					createdDateTime = longDateFormat.parse(existingAttribs.getCreatedDate());

				try {
					lastModifiedDateTime = longDateFormat.parse(vuln.getLastModifiedDate());
				} catch (Exception e) {
					lastModifiedDateTime = new Date();
					logger.error("Could not parse last modified date of Cve: {}, Err: {}\nCve data: {}", vuln.getLastModifiedDate(), e.toString(), vuln.toString());
					return false;
				}

				// calculate the time gap, if any
				int hours = (int) ChronoUnit.HOURS.between(createdDateTime.toInstant(), lastModifiedDateTime.toInstant());

				// if it did not exist in NVD, but found now, record time gap!
				if (!vulnAlreadyInNvd && vuln.existInNvd()) {
					vuln.setTimeGapNvd(hours);
					pstmt = connection.prepareStatement(updateVulnSqlNvd);
					pstmt.setInt(1, convertBoolToInt(vuln.existInNvd()));
					pstmt.setInt(2, vuln.getTimeGapNvd());
					pstmt.setString(3, vuln.getCveId());
					pstmt.executeUpdate();

					logger.info("CVE added to NVD! There is {} hours gap!\tCve data: {}", hours, vuln.toString());
					timeGapFound = true;
				}

				// if it did not exist in MITRE, but found now, record time gap!
				if (!vulnAlreaadyInMitre && vuln.existInMitre()) {
					vuln.setTimeGapMitre(hours);

					pstmt = connection.prepareStatement(updateVulnSqlMitre);
					pstmt.setInt(1, convertBoolToInt(vuln.existInMitre()));
					pstmt.setInt(2, vuln.getTimeGapMitre());
					pstmt.setString(3, vuln.getCveId());
					pstmt.executeUpdate();
					logger.info("CVE added to MITRE! There is {} hours gap!\tCve data: {}", hours, vuln.toString());
					timeGapFound = true;
				}
				return timeGapFound;

			} catch (Exception e) {
				logger.error("Error in checkTimeGaps() {}! Cve record time {}, Cve data {}", e.toString(), createdDateTime, vuln);
			}

		} // if

		return false;
	}

	/**
	 * Check if we need to record any time gaps for any CVE!
	 * 
	 * Simply check if an existing vulnerability (that did not exist at NVD/MITRE)
	 * is there NOW!
	 * 
	 * @param connection
	 * @param crawledVulnerabilityList
	 * @param existingVulnMap
	 */
	public int[] recordTimeGapsOfCrawledVulnerabilitiesForNvdMitre(Connection connection, List<CompositeVulnerability> crawledVulnerabilityList,
			Map<String, VulnerabilityAttribsForUpdate> existingVulnMap) {
		int existingCveCount = 0, newCveCount = 0, timeGapCount = 0;
		try {
			logger.info("Checking time gaps for " + crawledVulnerabilityList.size() + " CVEs! # of total CVEs in DB: " + existingVulnMap.size());

			for (CompositeVulnerability vuln : crawledVulnerabilityList) {
				try {
					if (existingVulnMap.containsKey(vuln.getCveId())) {
						VulnerabilityAttribsForUpdate existingAttribs = existingVulnMap.get(vuln.getCveId());
						// check time gap for vuln
						if (checkTimeGapsForCVE(vuln, connection, existingAttribs))
							timeGapCount++;
						existingCveCount++;
					} else
						newCveCount++;
				} catch (Exception e) {
					logger.error("Error while checking the time gap for CVE: {}. Err: {} ", vuln.toString(), e.toString());
				}
			}
			logger.info("Done! Checked time gaps for {} (of {}) CVEs! # of new CVEs: {}", existingCveCount, crawledVulnerabilityList.size(), newCveCount);
		} catch (Exception e) {
			logger.error("Error while checking time gaps for {} CVEs. ", crawledVulnerabilityList.size(), e.toString());
		}
		return new int[] { existingCveCount, newCveCount, timeGapCount };
	}

	/**
	 * Returns an ArrayList of Vulnerability objects gathered from all rows in the
	 * Vulnerability table.
	 * 
	 * @return A list of all Vulnerabilities in the Vulnerability table
	 */
	public ArrayList<Vulnerability> selectAllVuln() {
		ArrayList<Vulnerability> vulnList = new ArrayList<Vulnerability>();
		Connection conn = null;
		try {
			conn = getConnection();
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(selectVulnSql);

			while (rs.next()) {
				Vulnerability vuln = new Vulnerability();

				vuln.setVulnID(rs.getInt("vuln_id"));
				vuln.setCVEID(rs.getString("cve_id"));
				vuln.setDescription(rs.getString("description"));
				vuln.setPlatform(rs.getString("platform"));
				vuln.setIntroduceDate(rs.getString("introduced_date"));
				vuln.setPublishDate(rs.getString("published_date"));
				vuln.setCreateDate(rs.getString("created_date"));
				vuln.setLastModifiedDate(rs.getString("last_modified_date"));
				vuln.setFixDate(rs.getString("fixed_date"));
				vuln.setExistInMitre(convertIntToBool(rs.getInt("exists_at_mitre")));
				vuln.setExistInNvd(convertIntToBool(rs.getInt("exists_at_nvd")));
				vuln.setTimeGapNvd(rs.getInt("time_gap_nvd"));
				vuln.setTimeGapMitre(rs.getInt("time_gap_mitre"));

				vulnList.add(vuln);
			}

		} catch (SQLException e) {
			logger.error(e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}

		return vulnList;
	}

	/**
	 * Takes in a list of NvipSourceUrl objects (nvipSourceList) and updates the
	 * NvipSourceUrl table in the database.
	 * 
	 * @param nvipSourceList
	 * @param notOkUrls
	 * @return
	 */
	public boolean insertNvipSource(List<NvipSource> nvipSourceList, HashMap<String, Integer> notOkUrls) {
		HashMap<String, NvipSource> existingNvipSourceMap = new HashMap<String, NvipSource>();
		int insertedUrlCount = 0;
		int notOkUrlCount = 0;
		try (Connection conn = getConnection();
				PreparedStatement pstmt = conn.prepareStatement(insertNvipSourceSql);
				PreparedStatement pstmt2 = conn.prepareStatement(updateNvipSourceSql);
				Statement stmt = conn.createStatement();
				ResultSet rs = stmt.executeQuery(selectAllNvipSourceSql);) {

			while (rs.next()) {
				String sUrl = rs.getString("url");
				int httpStatus = rs.getInt("http_status");
				existingNvipSourceMap.put(sUrl, new NvipSource(sUrl, "", httpStatus));
			}

			// urls found
			for (int i = 0; i < nvipSourceList.size(); i++) {
				String nvipSourceUrl = null;
				try {
					nvipSourceUrl = nvipSourceList.get(i).getUrl();
					int httpStatus = nvipSourceList.get(i).getHttpStatus();

					if (existingNvipSourceMap.containsKey(nvipSourceUrl)) {
						continue; // next item
					}
					// does not exist, insert it!
					pstmt.setString(1, nvipSourceUrl);
					pstmt.setString(2, nvipSourceList.get(i).getDescription());
					pstmt.setInt(3, httpStatus);
					pstmt.executeUpdate();
					insertedUrlCount++;
				} catch (Exception e) {
					logger.error("Error while saving source url: " + nvipSourceUrl + ", continuing with the next one! " + e.toString());
				}
			}

			// not ok urls
			for (String nvipSourceUrl : notOkUrls.keySet()) {
				int httpStatus = notOkUrls.get(nvipSourceUrl);
				// update entry
				pstmt2.setInt(1, httpStatus);
				pstmt2.setString(2, nvipSourceUrl); // where
				pstmt2.executeUpdate();
				notOkUrlCount++;
			}
		} catch (SQLException e) {
			logger.error(e.getMessage());
			return false;
		}

		logger.info("Out of " + nvipSourceList.size() + " crawled URLs, " + insertedUrlCount + " of them were NEW and INSERTED into database!");
		logger.info(notOkUrlCount + " URLs were not reachable, http status codes saved to the database!");
		return true;
	}

	/**
	 * Returns an ArrayList of NvipSource objects gathered from all rows in the
	 * NvipSourceUrl table.
	 * 
	 * @return A list of all NvipSource in the NvipSourceUrl table
	 */
	public ArrayList<NvipSource> getNvipCveSources() {
		ArrayList<NvipSource> nvipSourceList = new ArrayList<NvipSource>();
		Connection conn = null;
		try {
			conn = getConnection();
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(selectAllNvipSourceSql);

			while (rs.next()) {
				int sourceId = rs.getInt("source_id");
				String url = rs.getString("url");
				String description = rs.getString("description");
				int httpStatus = rs.getInt("http_status");

				NvipSource nvipSource = new NvipSource(url, description, httpStatus);
				nvipSource.setSourceId(sourceId);
				nvipSourceList.add(nvipSource);
			}
		} catch (SQLException e) {
			logger.error(e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException ignored) {

			}
		}

		return nvipSourceList;
	}

	/**
	 * Check if the url exists in Nvip source list
	 * 
	 * @param url
	 * @return
	 */
	public boolean doesNvipSourceUrlExist(String url) {
		Connection conn = null;
		try {
			conn = getConnection();
			PreparedStatement pstmt = conn.prepareStatement(selectNvipSourceSql);
			pstmt.setString(1, url);
			ResultSet rs = pstmt.executeQuery();
			if (rs.next()) {
				return true;
			}
		} catch (SQLException e) {
			logger.error(e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException ignored) {
			}
		}
		return false;
	}

	/**
	 * Takes in a list of VulnSource objects (vulnSourceList) and inserts each into
	 * the VulnSourceUrl table in the database.
	 * 
	 * @param vulnSourceList List of VulnSource objects to be inserted
	 * @return true if successfully inserted, false if an exception occurred.
	 */
	public boolean insertVulnSource(List<VulnSource> vulnSourceList) {
		Connection conn = null;
		try {
			conn = getConnection();
			for (int i = 0; i < vulnSourceList.size(); i++) {
				PreparedStatement pstmt = conn.prepareStatement(insertVulnSourceSql);
				pstmt.setString(1, vulnSourceList.get(i).getCveId());
				pstmt.setString(2, vulnSourceList.get(i).getUrl());
				pstmt.executeUpdate();
			}

		} catch (SQLException e) {
			logger.error("Error inserting vuln sources: " + e.getMessage());
			return false;
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}
		return true;
	}

	/**
	 * With the same connection
	 * 
	 * @param vulnSourceList
	 * @param conn
	 * @return
	 */
	public boolean insertVulnSource(List<VulnSource> vulnSourceList, Connection conn) {
		try (PreparedStatement pstmt = conn.prepareStatement(insertVulnSourceSql);) {
			for (int i = 0; i < vulnSourceList.size(); i++) {
				pstmt.setString(1, vulnSourceList.get(i).getCveId());
				pstmt.setString(2, vulnSourceList.get(i).getUrl());
				pstmt.executeUpdate();
			}
		} catch (SQLException e) {
			logger.error(e.getMessage());
			return false;
		}
		return true;
	}

	/**
	 * Returns an ArrayList of VulnSource objects gathered from all rows in the
	 * VulnSourceUrl table.
	 * 
	 * @return A list of all VulnSource in the VulnSourceUrl table
	 */
	public ArrayList<VulnSource> selectAllVulnSource() {
		ArrayList<VulnSource> vulnSourceList = new ArrayList<VulnSource>();
		Connection conn = null;
		try {
			conn = getConnection();
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(selectVulnSourceSql);

			while (rs.next()) {
				String cveId = rs.getString("cve_id");
				String url = rs.getString("url");

				VulnSource vulnSource = new VulnSource(cveId, url);
				vulnSourceList.add(vulnSource);
			}

		} catch (SQLException e) {
			logger.error(e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}

		return vulnSourceList;
	}

	/**
	 * delete sources for the given cve id
	 * 
	 * @param cveId
	 * @return
	 */
	public int deleteVulnSource(String cveId) {
		Connection conn = null;
		try {
			conn = getConnection();
			PreparedStatement pstmt = conn.prepareStatement(deleteVulnSourceSql);
			pstmt.setString(1, cveId);
			int count = pstmt.executeUpdate();
			return count;
		} catch (SQLException e) {
			logger.error("Error in deleteVulnSource(): " + e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}
		return 0;
	}

	/**
	 * with the same connection
	 * 
	 * @param cveId
	 * @param conn
	 * @return
	 */
	public int deleteVulnSource(String cveId, Connection conn) {
		try {
			PreparedStatement pstmt = conn.prepareStatement(deleteVulnSourceSql);
			pstmt.setString(1, cveId);
			int count = pstmt.executeUpdate();
			return count;
		} catch (SQLException e) {
			logger.error(e.getMessage());
		}
		return 0;
	}

	/**
	 * Takes in a list of CVE objects (cveList) and checks if each CVE exists in the
	 * CVEActual table. If it does, then the udpateCveActual function is called. If
	 * not, then the insertCveHelper function is called. Finally, the
	 * inerstCveHistory function is called.
	 * 
	 * @param cveList List of CVE objects to be inserted
	 * @return true if successfully inserted, false if an exception occurred.
	 */
	public boolean insertCveActual(List<CVE> cveList) {
		HashMap<String, String> cveMap = new HashMap<>();
		Connection conn = null;
		try {
			conn = getConnection();
			for (int i = 0; i < cveList.size(); i++) {
				CVE cve = cveList.get(i);

				String selectSql = "SELECT * FROM CVEActual WHERE (cve_id = ? AND full_page_url = ?);";
				PreparedStatement pstmt = conn.prepareStatement(selectSql);
				pstmt.setString(1, cve.getCveId());
				pstmt.setString(2, cve.getFullPageUrl());

				ResultSet rs = pstmt.executeQuery();
				boolean isUniqueCve = true;

				while (rs.next()) {
					isUniqueCve = false;
					break;
				}

				if (!isUniqueCve) {
					updateCveActual(conn, cve);
				} else {
					insertCveHelper(conn, cve, insertCveActualSql);
				}
				insertCveHistory(conn, cve);
			}

		} catch (SQLException e) {
			logger.error(e.getMessage());
			return false;
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}
		return true;
	}

	/**
	 * Updates the CVEActual table with the CVE object (cve) passed in.
	 * 
	 * @param conn HikariCP connection to database
	 * @param cve  CVE object to be updated in database
	 * @throws SQLException
	 */
	private void updateCveActual(Connection conn, CVE cve) throws SQLException {
		PreparedStatement pstmt = conn.prepareStatement(updateCveActualSql);

		pstmt.setString(1, cve.getProcessedDate());
		pstmt.setString(2, cve.getCveContent());

		// These two setStrings are for the WHERE part of the update statement
		pstmt.setString(3, cve.getCveId());
		pstmt.setString(4, cve.getFullPageUrl());

		pstmt.executeUpdate();
	}

	/**
	 * Returns an ArrayList of CVE objects gathered from all rows in the CVEActual
	 * table.
	 * 
	 * @return A list of all CVE in the CVEActual table
	 */
	public ArrayList<CVE> selectAllCveActual() {
		ArrayList<CVE> cveList = new ArrayList<CVE>();
		cveList = selectCveHelper("CVEActual", selectCveActualSql);
		return cveList;
	}

	/**
	 * Inserts a new row into the CVEHistory table with the CVE object (cve) passed
	 * in
	 * 
	 * @param conn HikariCP connection to database
	 * @param cve  CVE object to be inserted in database
	 */
	private void insertCveHistory(Connection conn, CVE cve) throws SQLException {

		String selectSql = "SELECT * FROM CVEHistory WHERE (cve_id = ? AND full_page_url = ? AND processed_date = ?);";
		PreparedStatement pstmt = conn.prepareStatement(selectSql);
		pstmt.setString(1, cve.getCveId());
		pstmt.setString(2, cve.getFullPageUrl());
		pstmt.setString(3, cve.getProcessedDate());
		ResultSet rs = pstmt.executeQuery();

		boolean isUniqueToHistory = true;

		while (rs.next()) {
			isUniqueToHistory = false;
			break;
		}

		if (isUniqueToHistory) {
			insertCveHelper(conn, cve, insertCveHistorySql);
		} else {
			updateCveHistory(conn, cve);
		}
	}

	/**
	 * Updates the CVEHistory table with the CVE object (cve) passed in.
	 * 
	 * @param conn HikariCP connection to database
	 * @param cve  CVE object to be updated in database
	 * @throws SQLException
	 */
	public void updateCveHistory(Connection conn, CVE cve) throws SQLException {
		PreparedStatement pstmt = conn.prepareStatement(updateCveHistorySql);
		pstmt.setString(1, cve.getCveContent());

		// Used for the WHERE portion of the SQL statement
		pstmt.setString(2, cve.getCveId());
		pstmt.setString(3, cve.getFullPageUrl());
		pstmt.setString(4, cve.getProcessedDate());

		pstmt.executeUpdate();
	}

	/**
	 * Returns an ArrayList of CVE objects gathered from all rows in the CVEHistory
	 * table.
	 * 
	 * @return A list of all CVE in the CVEHistory table
	 */
	public ArrayList<CVE> selectAllCveHistory() {
		ArrayList<CVE> cveList = new ArrayList<CVE>();
		cveList = selectCveHelper("CVEHistory", selectCveHistorySql);
		return cveList;
	}

	/**
	 * A helper function to insert a CVE object into either the CVEActual or
	 * CVEHistory table, since the tables have the same columns
	 * 
	 * @param conn      HikariCP connection to database
	 * @param cve       CVE object to be inserted in database
	 * @param insertSql The insert sql statement to be used
	 * @throws SQLException
	 */
	private void insertCveHelper(Connection conn, CVE cve, String insertSql) throws SQLException {
		PreparedStatement pstmt = conn.prepareStatement(insertSql);

		pstmt.setString(1, cve.getCveId());
		pstmt.setString(2, cve.getFullPageUrl());
		pstmt.setString(3, cve.getProcessedDate());
		pstmt.setString(4, cve.getCveContent());
		pstmt.executeUpdate();
	}

	/**
	 * A helper function to select all entries in either the CVEActual and
	 * CVEHistory table, since the tables have the same columns
	 * 
	 * @param tableName Name of the table to gather rows from
	 * @param selectSql The select sql statement to be used
	 * @return cveList A list of all CVE in the "tableName" table
	 */
	private ArrayList<CVE> selectCveHelper(String tableName, String selectSql) {
		ArrayList<CVE> cveList = new ArrayList<CVE>();
		try (Connection conn = getConnection()) {
			if (!checkTableExist(conn, tableName)) {
				return cveList;
			}

			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(selectSql);

			while (rs.next()) {
				String cveId = rs.getString("cve_id");
				String fullPageUrl = rs.getString("full_page_url");
				String processedDate = rs.getString("processed_date");
				String cveContent = rs.getString("cve_content");

				CVE cve = new CVE(cveId, fullPageUrl, processedDate, cveContent);
				cveList.add(cve);
			}
			conn.close();
		} catch (SQLException e) {
			logger.error(e.getMessage());
		}

		return cveList;
	}

	/**
	 * Inserts <dailyRun> into the DailyRunHistory table in the database.
	 * 
	 * @param dailyRun
	 * @return max run_id
	 */
	public int insertDailyRun(DailyRun dailyRun) {
		ResultSet rs = null;
		int maxRunId = -1;
		Connection conn = null;
		try {
			conn = getConnection();
			Statement stmt = conn.createStatement();

			PreparedStatement pstmt = conn.prepareStatement(insertDailyRunSql);
			pstmt.setString(1, dailyRun.getRunDateTime());
			pstmt.setFloat(2, dailyRun.getCrawlTimeMin());
			pstmt.setInt(3, dailyRun.getTotalCveCount());
			pstmt.setInt(4, dailyRun.getNotInNvdCount());
			pstmt.setInt(5, dailyRun.getNotInMitreCount());
			pstmt.setInt(6, dailyRun.getNotInBothCount());
			pstmt.setInt(7, dailyRun.getNewCveCount());
			pstmt.setInt(8, dailyRun.getAddedCveCount());
			pstmt.setInt(9, dailyRun.getUpdatedCveCount());
			pstmt.executeUpdate();

			String maxRunIdSQL = "SELECT max(run_id) as run_id FROM nvip.dailyrunhistory";
			rs = stmt.executeQuery(maxRunIdSQL);
			if (rs.next()) {
				maxRunId = rs.getInt("run_id");
			}

		} catch (Exception e) {
			logger.error(e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}
		return maxRunId;
	}

	/**
	 * update DailyRun
	 * 
	 * @param runId
	 * @param dailyRun
	 * @return
	 */
	public int updateDailyRun(int runId, DailyRun dailyRun) {
		Connection conn = null;
		PreparedStatement pstmt = null;
		DecimalFormat df = new DecimalFormat("#.00");
		try {
			conn = getConnection();
			/**
			 * calculate avg nvd and mitre times
			 */
			Statement stmt = conn.createStatement();
			String cvgTimeSql = "SELECT avg(time_gap_mitre) as mitre FROM Vulnerability where time_gap_mitre > 0";
			ResultSet rs = stmt.executeQuery(cvgTimeSql);
			if (rs.next())
				dailyRun.setAvgTimeGapMitre(Double.parseDouble(formatter.format(rs.getDouble("mitre"))));

			cvgTimeSql = "SELECT avg(time_gap_nvd) as nvd FROM Vulnerability where time_gap_nvd > 0";
			rs = stmt.executeQuery(cvgTimeSql);
			if (rs.next())
				dailyRun.setAvgTimeGapNvd(Double.parseDouble(formatter.format(rs.getDouble("nvd"))));

			pstmt = conn.prepareStatement(updateDailyRunSql);
			// pstmt.setString(1, dailyRun.getRunDateTime());
			float crawlTime = Float.parseFloat(df.format(dailyRun.getCrawlTimeMin()));
			pstmt.setFloat(1, crawlTime);
			double dbTime = Double.parseDouble(df.format(dailyRun.getDatabaseTimeMin()));
			pstmt.setDouble(2, dbTime);
			pstmt.setInt(3, dailyRun.getTotalCveCount());
			pstmt.setInt(4, dailyRun.getNotInNvdCount());
			pstmt.setInt(5, dailyRun.getNotInMitreCount());
			pstmt.setInt(6, dailyRun.getNotInBothCount());
			pstmt.setInt(7, dailyRun.getNewCveCount());
			double avgNvdTime = Double.parseDouble(df.format(dailyRun.getAvgTimeGapNvd()));
			pstmt.setDouble(8, avgNvdTime);

			double avgMitreTime = Double.parseDouble(df.format(dailyRun.getAvgTimeGapMitre()));
			pstmt.setDouble(9, avgMitreTime);
			pstmt.setInt(10, runId);
			pstmt.executeUpdate();

		} catch (Exception e) {
			logger.error("Error in updateDailyRun()!  " + e.getMessage() + "\nSQL:" + pstmt.toString());
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}
		return runId;
	}

	/**
	 * Returns an ArrayList of DailyRun objects gathered from all rows in the
	 * DailyRunHistory table.
	 * 
	 * @return A list of all rows in the DailyRunHistory table as DailyRun objects
	 */
	public ArrayList<DailyRun> selectAllDailyRun() {
		ArrayList<DailyRun> dailyRunList = new ArrayList<DailyRun>();
		Connection conn = null;
		try {
			conn = getConnection();
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(selectDailyRunSql);

			while (rs.next()) {
				String runDateTime = rs.getString("run_date_time");
				float crawlTimeMin = rs.getFloat("crawl_time_min");
				int totalCveCount = rs.getInt("total_cve_count");
				int notInNvdCount = rs.getInt("not_in_nvd_count");
				int notInMitreCount = rs.getInt("not_in_mitre_count");
				int notInBothCount = rs.getInt("not_in_both_count");
				int newCveCount = rs.getInt("new_cve_count");
				float avgTimeGapNvd = rs.getFloat("avg_time_gap_nvd");
				float avgTimeGapMitre = rs.getFloat("avg_time_gap_mitre");

				DailyRun dailyRun = new DailyRun(runDateTime, crawlTimeMin, totalCveCount, notInNvdCount, notInMitreCount, notInBothCount, newCveCount, avgTimeGapNvd, avgTimeGapMitre);
				dailyRunList.add(dailyRun);
			}

		} catch (SQLException e) {
			logger.error(e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}

		return dailyRunList;
	}

	/**
	 * Insert vdo characteristic
	 * 
	 * @param vdoCharacteristicList
	 * @param conn
	 * @return
	 */
	public boolean insertVdoCharacteristic(List<VdoCharacteristic> vdoCharacteristicList, Connection conn) {
		try {
			for (int i = 0; i < vdoCharacteristicList.size(); i++) {
				PreparedStatement pstmt = conn.prepareStatement(insertVdoCharacteristicSql);
				pstmt.setString(1, vdoCharacteristicList.get(i).getCveId());
				pstmt.setInt(2, vdoCharacteristicList.get(i).getVdoLabelId());
				pstmt.setDouble(3, vdoCharacteristicList.get(i).getVdoConfidence());
				pstmt.setInt(4, vdoCharacteristicList.get(i).getVdoNounGroupId());
				pstmt.executeUpdate();
			}

		} catch (SQLException e) {
			logger.error("Error inserting VDO characterization: " + e.getMessage());
			return false;
		}
		return true;
	}

	/**
	 * Flush VDO data for CVE
	 * 
	 * @param cveId
	 * @param vdoCharacteristicList
	 * @param conn
	 */
	private void updateVdoLabels(String cveId, List<VdoCharacteristic> vdoCharacteristicList, Connection conn) throws SQLException {

		try (PreparedStatement pstmt = conn.prepareStatement(deleteVdoCharacteristicSql);) {
			pstmt.setString(1, cveId);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error(e.toString());
		}

		try (PreparedStatement pstmt = conn.prepareStatement(insertVdoCharacteristicSql);) {
			for (int i = 0; i < vdoCharacteristicList.size(); i++) {
				pstmt.setString(1, vdoCharacteristicList.get(i).getCveId());
				pstmt.setInt(2, vdoCharacteristicList.get(i).getVdoLabelId());
				pstmt.setDouble(3, vdoCharacteristicList.get(i).getVdoConfidence());
				pstmt.setInt(4, vdoCharacteristicList.get(i).getVdoNounGroupId());
				pstmt.executeUpdate();
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}

	}

	/**
	 * Insert cvss scores
	 * 
	 * @param cvssScoreList
	 * @return
	 */
	public void insertCvssScore(List<CvssScore> cvssScoreList, Connection conn) {

		for (int i = 0; i < cvssScoreList.size(); i++) {
			try (PreparedStatement pstmt = conn.prepareStatement(insertCvssScoreSql);) {
				pstmt.setString(1, cvssScoreList.get(i).getCveId());
				pstmt.setInt(2, cvssScoreList.get(i).getSeverityId());
				pstmt.setDouble(3, cvssScoreList.get(i).getSeverityConfidence());
				pstmt.setString(4, cvssScoreList.get(i).getImpactScore());
				pstmt.setDouble(5, cvssScoreList.get(i).getImpactConfidence());
				pstmt.executeUpdate();
			} catch (SQLException e) {
				logger.error(e.toString());
			}
		}
	}

	/**
	 * Delete cvss for cve
	 * 
	 * @param cveId
	 * @return
	 */
	public int deleteCvssScore(String cveId, Connection conn) {
		try (PreparedStatement pstmt = conn.prepareStatement(deleteCvssScoreSql);) {
			pstmt.setString(1, cveId);
			return pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		return 0;
	}

	/**
	 * Delete daily run
	 * 
	 * @param datetime
	 * @return
	 */
	public int deleteDailyRun(String datetime) {
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(deleteDailyRunSql);) {
			pstmt.setString(1, datetime);
			return pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error(e.getMessage());
		}
		return 0;
	}

	/**
	 * Delete vulnerability
	 * 
	 * @param cveId
	 * @return
	 */
	public int deleteVuln(String cveId) {
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(deleteVulnSql);) {
			pstmt.setString(1, cveId);
			return pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error(e.getMessage());
		}
		return 0;
	}

	/**
	 * IMPORTANT NOTE: Please do not use this method. Use getInstance() instead.
	 * This method is used while storing tens of thousands of CVEs with
	 * multi-threading.
	 * 
	 * 
	 * If you need to use this method, do not forget to invoke shutdown() when you
	 * are done!
	 * 
	 * @return
	 */
	public static DatabaseHelper getInstanceForMultiThreading() {
		return new DatabaseHelper();
	}

	/**
	 * Hikari active connections
	 * 
	 * @return
	 */
	public int getActiveConnections() {
		return dataSource.getHikariPoolMXBean().getActiveConnections();
	}

	/**
	 * Hikari idle connections
	 * 
	 * @return
	 */
	public int getIdleConnections() {
		return dataSource.getHikariPoolMXBean().getIdleConnections();
	}

	/**
	 * Hikari total connections!
	 * 
	 * @return
	 */
	public int getTotalConnections() {
		return dataSource.getHikariPoolMXBean().getTotalConnections();
	}

	/**
	 * active, idle and total connections on the current instance
	 * 
	 * @return
	 */
	public String getConnectionStatus() {
		return "[" + getActiveConnections() + "," + this.getIdleConnections() + "]=" + getTotalConnections();
	}

	/**
	 * shut down connection pool. U
	 */
	public void shutdown() {
		dataSource.close();
		config = null;
	}

	/**
	 * delete vulnerability updates by run
	 * 
	 * @param runId
	 * @return
	 */
	public int deleteVulnerabilityUpdate(int runId) {
		logger.info("Deleting db updates for run id {}", runId);
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(deleteVulnerabilityUpdateSql);) {
			pstmt.setInt(1, runId);
			return pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error(e.getMessage());
		}
		return 0;
	}

	/**
	 * clear existing CVEs map
	 */
	public static void clearExistingVulnMap() {
		existingVulnMap.clear();
	}

	/**
	 * get vulnerability Id(s) of the CVE
	 * 
	 * @param cveId
	 * @return
	 */
	public List<Integer> getVulnerabilityIdList(String cveId) {
		List<Integer> vulnIdList = new ArrayList<Integer>();
		Connection conn = null;
		PreparedStatement pstmt = null;
		try {
			conn = getConnection();
			pstmt = conn.prepareStatement(selectVulnerabilityIdSql);
			pstmt.setString(1, cveId);
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				vulnIdList.add(rs.getInt("vuln_id"));
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		} finally {
			try {
				if (pstmt != null)
					pstmt.close();
				if (conn != null)
					conn.close();
			} catch (SQLException ignored) {
			}
		}
		return vulnIdList;
	}

	/**
	 * get defined cvss severity labels as hash map
	 * 
	 * @return
	 */
	public Map<String, Integer> getCvssSeverityLabels() {
		return getTableDataAsHashMap(selectCvssSeveritySql, "cvss_severity_id", "cvss_severity_class");
	}

	/**
	 * get vdo labels as hash map
	 * 
	 * @return
	 */
	public Map<String, Integer> getVdoLabels() {
		return getTableDataAsHashMap(selectVdoLabelSql, "vdo_label_id", "vdo_label_name");
	}

	public Map<String, Integer> getVdoNounGrpups() {
		return getTableDataAsHashMap(selectVdoNounGroupSql, "vdo_noun_group_id", "vdo_noun_group_name");
	}

	/**
	 * get table data as Map<name,id>
	 * 
	 * @param sqlSentence
	 * @param intField
	 * @param stringField
	 * @return
	 */
	public Map<String, Integer> getTableDataAsHashMap(String sqlSentence, String intField, String stringField) {
		Map<String, Integer> cvssSeverityLabels = new HashMap<String, Integer>();
		Connection conn = null;
		try {
			conn = getConnection();
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(sqlSentence);

			while (rs.next()) {
				int id = rs.getInt(intField);
				String name = rs.getString(stringField);
				cvssSeverityLabels.put(name, id);
			}
		} catch (SQLException e) {
			logger.error(e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}
		return cvssSeverityLabels;
	}

	/**
	 * delete the source url from the crawled URLs list
	 * 
	 * @param sourceUrl
	 * @return
	 */
	public int deleteNvipSourceUrl(String sourceUrl) {
		try (Connection conn = getConnection();) {

			PreparedStatement pstmt = conn.prepareStatement(deleteNvipSourceSql);
			pstmt.setString(1, sourceUrl);
			int count = pstmt.executeUpdate();
			return count;
		} catch (SQLException e) {
			logger.error("Error while removing source url: {}, {} ", sourceUrl, e);
		}
		return 0;
	}

	public int flushNvipSourceUrl() {
		try (Connection conn = getConnection();) {
			PreparedStatement pstmt = conn.prepareStatement(deleteAllNvipSourceSql);
			int count = pstmt.executeUpdate();
			return count;
		} catch (SQLException e) {
			logger.error("Error while flushing source urls {} ", e);
		}
		return 0;
	}

	/**
	 * Store exploits for CVE. Assumes that the CVE exists in the database
	 * 
	 * @param vulnerability
	 * @param exploitList
	 * @return
	 */
	public boolean saveExploits(CompositeVulnerability vulnerability, List<Exploit> exploitList, Map<String, VulnerabilityAttribsForUpdate> existingVulnMap) {

		Connection connection;
		try {
			connection = getConnection();
		} catch (SQLException e1) {
			logger.error("Error while obtaining db connection, Error: {}", e1.toString());
			return false;
		}

		try {
			if (!existingVulnMap.containsKey(vulnerability.getCveId())) {
				logger.warn("Vulnerability does not exist in the database, you can not add exploits for it! Vulnerability: {}", vulnerability);
				return false;
			}

			VulnerabilityAttribsForUpdate existingAttribs = existingVulnMap.get(vulnerability.getCveId());

			// remove existing exploits for CVE
			deleteExploits(connection, existingAttribs.getVulnId());

			// insert new exploits
			for (Exploit exploit : exploitList) {
				exploit.setVulnId(existingAttribs.getVulnId()); // set vulnerability ID from DB
				insertExploit(connection, exploit);
			}

		} catch (Exception e) {
			logger.error("Error while recording {} exploits for CVE:{}, Error: {}", exploitList.size(), vulnerability.getCveId(), e);
			return false;
		} finally {
			try {
				connection.close();
			} catch (Exception e) {
			}
		}

		return true;
	}

	/**
	 * save exploit
	 * 
	 * @param exploit
	 * @return
	 */
	public boolean insertExploit(Connection connection, Exploit exploit) throws SQLException {
		PreparedStatement pstmt = null;
		try {
			pstmt = connection.prepareStatement(insertExploitSql);

			/**
			 * "INSERT INTO Exploit (vuln_id, cve_id, publisher_id, publish_date,
			 * publisher_url, description, exploit_code, nvip_record_date) VALUES
			 * (?,?,?,?,?,?,?,?);";
			 * 
			 */
			pstmt.setInt(1, exploit.getVulnId());
			pstmt.setString(2, exploit.getCveId());
			pstmt.setInt(3, exploit.getPublisherId());
			pstmt.setString(4, exploit.getPublishDate());
			pstmt.setString(5, exploit.getPublisherUrl());
			pstmt.setString(6, exploit.getDescription());
			pstmt.setString(7, exploit.getExploitCode());
			pstmt.setString(8, exploit.getNvipRecordDate());

			pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error("Error while saving exploit! " + e.getMessage() + "\n" + pstmt.toString() + "\tExploit: " + exploit.toString());
			return false;
		} finally {
			if (pstmt != null)
				pstmt.close();
		}
		return true;
	}

	/**
	 * delete exploits of this vulnerability from DB
	 * 
	 * @param exploit
	 * @return
	 */
	public int deleteExploits(Connection connection, int vulnerabilityId) {
		try (PreparedStatement pstmt = connection.prepareStatement(deleteExploitSql);) {
			pstmt.setInt(1, vulnerabilityId);
			return pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		return 0;
	}

	public int updateVulnerabilityDataFromCsv(CompositeVulnerability vuln, Map<String, VulnerabilityAttribsForUpdate> existingVulnMap, int runId) throws SQLException {
		Connection connection = getConnection();
		try {
			VulnerabilityAttribsForUpdate existingAttribs = existingVulnMap.get(vuln.getCveId());
			if (existingAttribs == null) {
				try (PreparedStatement pstmt = connection.prepareStatement(insertVulnDescriptionSql);) {
					// insert
					pstmt.setString(1, vuln.getCveId());
					pstmt.setString(2, vuln.getDescription());
					pstmt.executeUpdate();
				} catch (SQLException e1) {
					logger.error("Error while inserting vuln {} -- {}", vuln, e1.toString());
				}
			} else {
				try (PreparedStatement pstmt = connection.prepareStatement(updateVulnDescriptionSql);) {
					// update vulnerability
					pstmt.setString(1, vuln.getDescription());
					pstmt.setString(2, vuln.getCveId());
					pstmt.executeUpdate();
				} catch (SQLException e1) {
					logger.error("Error while updating vuln {} -- {}", vuln, e1.toString());
				}
			}

			/**
			 * vdo characters
			 */
			if (!vuln.getVdoCharacteristicInfo().isEmpty()) {
				updateVdoLabels(vuln.getCveId(), vuln.getVdoCharacteristicInfo(), connection);

				deleteCvssScore(vuln.getCveId(), connection); // clear existing ones
				insertCvssScore(vuln.getCvssScoreInfo(), connection); // add them
			}
			return 1; // done
		} catch (Exception e) {
			logger.error(e.toString());
		} finally {
			connection.close();
		}

		return 0;
	} // updateVuln

	public int getMaxRunId() {
		String maxRunIdSQL = "SELECT max(run_id) as run_id FROM nvip.dailyrunhistory";
		try (Connection connection = getConnection(); ResultSet rs = connection.createStatement().executeQuery(maxRunIdSQL);) {
			int maxRunId = 0;
			if (rs.next())
				maxRunId = rs.getInt("run_id");
			return maxRunId;
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		return 0;
	}

}