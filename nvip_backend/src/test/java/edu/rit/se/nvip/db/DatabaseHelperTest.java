package edu.rit.se.nvip.db;

import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import edu.rit.se.nvip.model.*;
import edu.rit.se.nvip.model.CompositeVulnerability.CveReconcileStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;


import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Collection of tests for the DatabaseHelper class. The general approach here it to use mocking/spying in order to
 * sever dependenies on database connections. Generally, SQL arguments are verified, execute commands are verified, and
 * return values are verified where applicable.
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class DatabaseHelperTest {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private DatabaseHelper dbh;
	@Mock
	private HikariDataSource hds;
	@Mock
	private Connection conn;
	@Mock
	private PreparedStatement pstmt;
	@Mock
	private ResultSet res;

	private void setMocking() {
		try {
			when(hds.getConnection()).thenReturn(conn);
			when(conn.prepareStatement(any())).thenReturn(pstmt);
			when(pstmt.executeQuery()).thenReturn(res);
			when(conn.createStatement()).thenReturn(pstmt);
			when(pstmt.executeQuery(any())).thenReturn(res);
		} catch (SQLException ignored) {}
	}

	/**
	 * Sets up the "databse" results to return n rows
	 * @param n Number of rows (number of times next() will return true)
	 */
	private void setResNextCount(int n) {
		try {
			when(res.next()).thenAnswer(new Answer<Boolean>() {
				private int iterations = n;
				public Boolean answer(InvocationOnMock invocation) {
					return iterations-- > 0;
				}
			});
		} catch (SQLException ignored) {}
	}

	/**
	 * Helper method for populating the "database" results.
	 * @param getStringArg Name of the column to retrieve from. Used for that column's value as well with a suffix.
	 * @param count Number of results to populate.
	 */
	private void setResStrings(String getStringArg, int count) {
		try {
			when(res.getString(getStringArg)).thenAnswer(new Answer<String>() {
				private int index = 0;

				public String answer(InvocationOnMock invocation) {
					if (index == count) {
						return null;
					}
					return getStringArg + index++;
				}
			});
		} catch (SQLException ignored) {}
	}

	/**
	 * Helper method for populating the "database" results. Just returns multiples of 1337
	 * @param getIntArg Name of the column to retrieve from.
	 * @param count Number of results to populate.
	 */
	private void setResInts(String getIntArg, int count) {
		try {
			when(res.getInt(getIntArg)).thenAnswer(new Answer<Integer>() {
				private int index = 0;

				public Integer answer(InvocationOnMock invocation) {
					if (index == count) {
						return 0;
					}
					return 1337 * index++;
				}
			});
		} catch (SQLException ignored) {}
	}

	private List<AffectedRelease> buildDummyReleases(int count) {
		List<AffectedRelease> releases = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			releases.add(new AffectedRelease(1337, "cve"+i, "cpe"+i, "date"+i, "version"+i));
		}
		return releases;
	}

	@org.junit.BeforeClass
	public static void classSetUp() {
		// forces a constructor, only want to do once
		DatabaseHelper.getInstance();
	}

	@org.junit.Before
	public void setUp() {
		this.dbh = DatabaseHelper.getInstance();
		ReflectionTestUtils.setField(this.dbh, "dataSource", this.hds);
		this.setMocking();
	}

	@org.junit.AfterClass
	public static void tearDown() {
		DatabaseHelper dbh = DatabaseHelper.getInstance();
		ReflectionTestUtils.setField(dbh, "databaseHelper", null);

	}

	@Test
	public void getInstanceTest() {
		assertNotNull(DatabaseHelper.getInstance());
	}

	@Test
	public void getConnectionTest() {
		try {
			Connection conn = dbh.getConnection();
			assertNotNull(conn);
		} catch (SQLException ignored) {}
	}

	@Test
	public void testDbConnectionTest() {
		try {
			assertTrue(this.dbh.testDbConnection());
			when(hds.getConnection()).thenReturn(null);
			assertFalse(this.dbh.testDbConnection());
		} catch (SQLException ignored) {}
	}

	@Test
	public void insertCpeProductsTest() {
		List<Product> testProducts = new ArrayList<>();
		String domain = "domain";
		String cpe = "cpe";
		for (int i=0; i < 5; i++) {
			testProducts.add(new Product(domain+i, cpe+i));
		}
		try {
			setResNextCount(0);
			when(pstmt.executeUpdate()).thenReturn(1);
			int count1 = dbh.insertCpeProducts(testProducts.subList(0,1));
			assertEquals(1, count1);

			int n_existing = 1;
			setResNextCount(n_existing);
			when(res.getInt(1)).thenReturn(n_existing);
			int count2 = dbh.insertCpeProducts(testProducts);
			assertEquals(4, count2);
			verify(pstmt, times(2)).setString(1, cpe+4);
			verify(pstmt).setString(2, domain+4);
		} catch (SQLException ignored) {}
	}

	@Test
	public void getCPEByIdTest() {
		String testCpe = "getCpeByIdTestCpe";

		try {
			int prodId = 1337;
			setResNextCount(1);
			when(res.getString("cpe")).thenReturn(testCpe);
			Map<String, ArrayList<String>> cpe = dbh.getCPEById(prodId);
			assertEquals(1, cpe.size());
			assertTrue(cpe.containsKey(testCpe));
			verify(pstmt).setInt(1, prodId);

			setResNextCount(0);
			cpe = dbh.getCPEById(0);
			assertEquals(0, cpe.size());
		} catch (SQLException ignored) {}
	}

	@Test
	public void getPatchSourceIdTest() {
		try {
			String address = "testaddress";
			int expectedId = 1;
			setResNextCount(1);
			when(res.getInt("source_url_id")).thenReturn(expectedId);
			int id = dbh.getPatchSourceId(address);
			verify(pstmt).setString(1, address);
			assertEquals(expectedId, id);

			setResNextCount(0);
			id = dbh.getPatchSourceId("testaddress");
			assertEquals(-1, id);
		} catch (SQLException ignored) {}
	}

	@Test
	public void insertPatchSourceURLTest() {
		try {
			int vulnArg = 1337;
			String urlArg = "test";
			assertTrue(dbh.insertPatchSourceURL(vulnArg	, urlArg));
			verify(pstmt).setInt(1, vulnArg);
			verify(pstmt).setString(2, urlArg);
			verify(pstmt).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteCommitsTest() {
		try {
			int arg = 1337;
			dbh.deleteCommits(arg);
			verify(pstmt).setInt(1, arg);
			verify(pstmt).executeUpdate();
		} catch (SQLException ignored) {}
	}


	@Test
	public void deltePatchURLTest() {
		try {
			int arg = 1337;
			dbh.deletePatchURL(arg);
			verify(pstmt).setInt(1, arg);
			verify(pstmt).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void getCPEsByCVETest() {
		String testCVEId = "testCVEId";
		int resCount = 2;
		setResNextCount(resCount);
		setResStrings("vuln_id", resCount);
		setResStrings("cve_id", resCount);
		setResStrings("cpe", resCount);

		Map<String, ArrayList<String>> cpes = dbh.getCPEsByCVE(testCVEId);
		assertEquals(resCount, cpes.size());
		assertTrue(cpes.containsKey("cpe0"));
		assertEquals("vuln_id0", cpes.get("cpe0").get(0));
		assertEquals("cve_id0", cpes.get("cpe0").get(1));
		try {
			verify(pstmt).setString(1, testCVEId);
		} catch (SQLException ignored) {}

		setResNextCount(0);
		cpes = dbh.getCPEsByCVE(testCVEId);
		assertEquals(0, cpes.size());
	}

	@Test
	public void getCPEsAndCVETest() {
		int resCount = 5;
		setResNextCount(5);
		setResStrings("vuln_id", resCount);
		setResStrings("cve_id", resCount);
		setResStrings("cpe", resCount);

		Map<String, ArrayList<String>> cpes = dbh.getCPEsAndCVE();
		assertEquals(resCount, cpes.size());
		assertTrue(cpes.containsKey("cpe4"));
		assertEquals("vuln_id4", cpes.get("cpe4").get(0));
		assertEquals("cve_id4", cpes.get("cpe4").get(1));

		setResNextCount(0);
		cpes = dbh.getCPEsAndCVE();
		assertEquals(0, cpes.size());
	}

	@Test
	public void getProdIdFromCpeTest() {
		int outId = 1337;
		String cpe = "cpe";

		try {
			setResNextCount(1);
			when(res.getInt("product_id")).thenReturn(outId);
			int prodId = dbh.getProdIdFromCpe(cpe);
			verify(pstmt).setString(1, cpe);
			assertEquals(outId, prodId);

			setResNextCount(0);
			assertEquals(-1, dbh.getProdIdFromCpe(cpe));
		} catch (SQLException ignored) {}
	}

	@Test
	public void insertAffectedReleasesV2Test() {
		int inCount = 5;
		List<AffectedRelease> releases = buildDummyReleases(inCount);
		dbh.insertAffectedReleasesV2(releases);
		try {
			verify(pstmt, atLeast(inCount*3)).setString(anyInt(), any());
			verify(pstmt, times(inCount)).setInt(anyInt(), anyInt());
			verify(pstmt, times(inCount)).executeUpdate();
			verify(pstmt).setString(4, releases.get(0).getVersion());
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteAffectedReleasesTest() {
		int count = 5;
		List<AffectedRelease> releases = buildDummyReleases(count);
		dbh.deleteAffectedReleases(releases);
		try {
			verify(pstmt, times(count)).setString(anyInt(), any());
			verify(pstmt, times(count)).executeUpdate();
			verify(pstmt).setString(1, releases.get(count-1).getCveId());
		} catch (SQLException ignored) {}
	}

	@Test
	public void getExistingVulnerabilitiesTest() {
		// static field so need to reset to retain test independence
		ReflectionTestUtils.setField(this.dbh, "existingVulnMap", new HashMap<String, Vulnerability>());
		int count = 5;
		setResNextCount(count);
		setResInts("vuln_id", count);
		setResStrings("cve_id", count);
		setResStrings("description", count);
		setResStrings("created_date", count);
		setResInts("exists_at_nvd", count);
		setResInts("exists_at_mitre", count);

		Map<String, Vulnerability> vulns = dbh.getExistingVulnerabilities();
		assertEquals(count, vulns.size());
		assertTrue(vulns.containsKey("cve_id4"));
		assertEquals(1337*4, vulns.get("cve_id4").getVulnID());
		assertEquals("cve_id4", vulns.get("cve_id4").getCveId());
		assertEquals("description4", vulns.get("cve_id4").getDescription());
		assertEquals("created_date4", vulns.get("cve_id4").getCreateDate());
		assertTrue(vulns.get("cve_id4").doesExistInNvd());
		assertTrue(vulns.get("cve_id4").doesExistInMitre());
		try {
			verify(pstmt).executeQuery();
		} catch (SQLException ignored) {}
		// should pull the vulnerabilities from memory instead of the db
		vulns = dbh.getExistingVulnerabilities();
		assertEquals(count, vulns.size());
		verifyNoMoreInteractions(pstmt);
	}

	@Test
	public void recordVulnerabilityListTest() {
		// static field so need to reset to retain test independence
		ReflectionTestUtils.setField(this.dbh, "existingVulnMap", new HashMap<String, Vulnerability>());
		int existingCount = 5;
		setResNextCount(existingCount);
		setResInts("vuln_id", existingCount);
		setResStrings("cve_id", existingCount);
		setResStrings("description", existingCount);
		setResStrings("created_date", existingCount);
		setResInts("exists_at_nvd", existingCount);
		setResInts("exists_at_mitre", existingCount);
		// one vulnerability should already exist, one is new
		List<CompositeVulnerability> vulns = new ArrayList<>();
		vulns.add(new CompositeVulnerability(1337*6, "url", "cve_id6", "platform", "pubdate", "moddate", "description", "domain"));
		vulns.add(new CompositeVulnerability(1337, "url", "cve_id1", "platform", "pubdate", "moddate", "description", "domain"));
		DatabaseHelper spyDB = spy(dbh);
		ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
		boolean success = spyDB.recordVulnerabilityList(vulns, 1111);
		try {
			verify(spyDB).updateVulnerability(any(), any(), any(), captor.capture());
			assertEquals(1111, (int) captor.getValue());
			verify(pstmt, atLeast(8)).setString(anyInt(), any());
			verify(pstmt, atLeast(4)).setInt(anyInt(), anyInt());
			verify(pstmt, atLeastOnce()).executeUpdate();
			verify(pstmt, atLeastOnce()).setString(1, "cve_id6");
			verify(spyDB).insertVulnSource(any(), any());
			verify(spyDB).insertVdoCharacteristic(any(), any());
			verify(spyDB).insertCvssScore(any(), any());
			verify(spyDB).checkNvdMitreStatusForCrawledVulnerabilityList(any(), any(), any());
		} catch (SQLException ignored) {}
		assertTrue(success);
	}

	@Test
	public void updateVulnerabilityTest() {
		String id = "cve_id0";
		ReflectionTestUtils.setField(this.dbh, "existingVulnMap", new HashMap<String, Vulnerability>());
		CompositeVulnerability vuln = new CompositeVulnerability(1337, "url", id, "platform", "pubdate", "moddate", "description", "domain");
		HashMap<String, Vulnerability> existing = new HashMap<>();
		existing.put(id, vuln);
		try {
			vuln.setCveReconcileStatus(CveReconcileStatus.DO_NOT_CHANGE);
			assertEquals(0, dbh.updateVulnerability(vuln, conn, existing, 1111));

			DatabaseHelper spyDB = spy(dbh);
			vuln.setCveReconcileStatus(CveReconcileStatus.UPDATE);
			assertEquals(1, spyDB.updateVulnerability(vuln, conn, existing, 1111));
			verify(pstmt, atLeast(7)).setString(anyInt(), anyString());
			ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
			verify(pstmt, atLeastOnce()).setString(anyInt(), captor.capture());
			assertTrue(captor.getAllValues().contains(id));
			verify(spyDB).deleteVulnSource(id, conn);
			verify(spyDB).insertVulnSource(vuln.getVulnSourceList(), conn);
			verify(spyDB).deleteCvssScore(id, conn);
			verify(spyDB).insertCvssScore(vuln.getCvssScoreInfo(), conn);
			verify(spyDB).insertVulnerabilityUpdate(1337, "description", "description", 1111, conn);
		} catch (SQLException ignore) {}
	}

	@Test
	public void insertVulnerabilityUpdateTest() {
		boolean success = dbh.insertVulnerabilityUpdate(1337, "description", "descriptionval", 1111, conn);
		assertTrue(success);
		try {
			verify(pstmt).setInt(1, 1337);
			verify(pstmt).setString(2, "description");
			verify(pstmt).setString(3, "descriptionval");
			verify(pstmt).setInt(4, 1111);
			verify(pstmt).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void addToCveStatusChangeHistoryTest() {
		String id = "cvd_id0";
		String date1 = "2023-01-01 00:00:00";
		String date2 = "2023-01-01 10:00:00";
		CompositeVulnerability vuln = new CompositeVulnerability(1337, "url", id, "platform", "pubdate", date2, "description", "domain");
		Vulnerability existing = new Vulnerability(1337, id, "description", 1, 1, date1);
		boolean success = dbh.addToCveStatusChangeHistory(vuln, conn, existing, "NVD", 0, 1, true, 10);
		assertTrue(success);
		try {
			verify(pstmt, times(3)).setString(anyInt(), any());
			verify(pstmt, times(5)).setInt(anyInt(), anyInt());
			verify(pstmt, atMost(2)).setTimestamp(anyInt(), any());
			verify(pstmt).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void checkNvdMitreStatusForCrawledVulnerabilityListTest() {
		String existing_id = "cve_id0";
		List<CompositeVulnerability> crawled = new ArrayList<>();
		crawled.add(new CompositeVulnerability(1337, "url", existing_id, "platform", "pubdate", "2023-01-01 10:00:00", "description", "domain"));
		crawled.add(new CompositeVulnerability(1337, "url", "cve_id5", "platform", "pubdate", "2023-01-31 00:00:00", "description", "domain"));
		Map<String, Vulnerability> existing = new HashMap<>();
		existing.put(existing_id, new Vulnerability(1337, existing_id, "description", 1, 1, "2023-01-01 00:00:00"));
		int[] out = dbh.checkNvdMitreStatusForCrawledVulnerabilityList(conn, crawled, existing);
		assertEquals(1, out[0]);
		assertEquals(1, out[1]);
		assertEquals(0, out[2]);
	}

	@Test
	public void insertNvipSourceTest() {
		List<NvipSource> sourceList = new ArrayList<>();
		HashMap<String, Integer> badURLs = new HashMap<>();
		sourceList.add(new NvipSource("url1", "des1", 200));
		sourceList.add(new NvipSource("url5", "des5", 200));
		badURLs.put("bad.com", 403);
		badURLs.put("bad.gov", 418);
		setResNextCount(3);
		setResStrings("url", 3);
		setResInts("http_status", 3);
		try {
			boolean success = dbh.insertNvipSource(sourceList, badURLs);
			assertTrue(success);
			verify(pstmt).setString(1, "url5");
			verify(pstmt).setString(2, "bad.gov");
			verify(pstmt, times(3)).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void getNvipCveSourcesTest() {
		setResNextCount(3);
		setResInts("source_id", 3);
		setResStrings("url", 3);
		setResStrings("description", 3);
		setResInts("http_status", 3);
		ArrayList<NvipSource> sources = dbh.getNvipCveSources();
		assertEquals(3, sources.size());
		NvipSource testSource = sources.get(2);
		assertEquals(1337*2, testSource.getSourceId());
		assertEquals("url2", testSource.getUrl());
		assertEquals("description2", testSource.getDescription());
		assertEquals(1337*2, testSource.getHttpStatus());
	}

	@Test
	public void insertVulnSourcesTest() {
		List<VulnSource> vulns = new ArrayList<>();
		vulns.add(new VulnSource("cve0", "url0"));
		vulns.add(new VulnSource("cve1", "url1"));
		boolean success = dbh.insertVulnSource(vulns, conn);
		assertTrue(success);
		try {
			verify(pstmt, times(2*2)).setString(anyInt(), anyString());
			verify(pstmt, times(2)).executeUpdate();
			verify(pstmt).setString(1, "cve0");
			verify(pstmt).setString(2, "url1");
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteVulnSourceTest() {
		try {
			when(pstmt.executeUpdate()).thenReturn(1);
			int out = dbh.deleteVulnSource("cveid");
			assertEquals(1, out);
			verify(pstmt).setString(1, "cveid");

			when(pstmt.executeUpdate()).thenThrow(new SQLException());
			out = dbh.deleteVulnSource("notAValidID");
			assertEquals(0, out);
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteVulnSourceMultiArgTest() {
		try {
			when(pstmt.executeUpdate()).thenReturn(1);
			int out = dbh.deleteVulnSource("cveid", conn);
			assertEquals(1, out);
			verify(pstmt).setString(1, "cveid");

			when(pstmt.executeUpdate()).thenThrow(new SQLException());
			out = dbh.deleteVulnSource("notAValidID", conn);
			assertEquals(0, out);
		} catch (SQLException ignored) {}
	}

	@Test
	public void insertDailyRunTest() {
		DailyRun run = new DailyRun("2023-01-01 00:00:00", 120, 10, 5, 3, 2, 8, 6, 7);
		setResNextCount(1);
		try {
			when(res.getInt("run_id")).thenReturn(99);
			int out = dbh.insertDailyRun(run);
			assertEquals(99, out);
			verify(pstmt).setString(1, "2023-01-01 00:00:00");
			verify(pstmt).setFloat(2, 120);
			verify(pstmt).setInt(3, 10);
			verify(pstmt).setInt(4, 5);
			verify(pstmt).setInt(5, 3);
			verify(pstmt).setInt(6, 2);
			verify(pstmt).setInt(7, 8);
			verify(pstmt).setInt(8, 0);
			verify(pstmt).setInt(9, 0);
			verify(pstmt).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void updateDailyRunTest() {
		DailyRun run = new DailyRun("2023-01-01 00:00:00", 120, 10, 5, 3, 2, 8, 6, 7);
		run.setDatabaseTimeMin(90.0);
		setResNextCount(2);
		try {
			when(res.getDouble("mitre")).thenReturn(2.71828);
			when(res.getDouble("nvd")).thenReturn(1.61803);
			int out = dbh.updateDailyRun(1111, run);
			assertEquals(1111, out);
			verify(pstmt).setFloat(1, (float) 120.00);
			verify(pstmt).setDouble(2, run.getDatabaseTimeMin());
			verify(pstmt, times(6)).setInt(anyInt(), anyInt());
			verify(pstmt).setDouble(8, 1.62);
			verify(pstmt).setDouble(9, 2.72);
			verify(pstmt).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void insertVdoCharacteristicTest() {
		List<VdoCharacteristic> vdos = new ArrayList<>();
		vdos.add(new VdoCharacteristic("cve0", 0, 0.8, 100));
		vdos.add(new VdoCharacteristic("cve1", 1, 0.2, 101));
		boolean success = dbh.insertVdoCharacteristic(vdos, conn);
		assertTrue(success);
		try {
			verify(pstmt, times(2)).setString(anyInt(), any());
			verify(pstmt, times(2*2)).setInt(anyInt(), anyInt());
			verify(pstmt, times(2)).setDouble(anyInt(), anyDouble());
			verify(pstmt, times(2)).executeUpdate();
			verify(pstmt).setString(1, "cve0");
			verify(pstmt).setString(1, "cve1");
			verify(pstmt).setInt(2, 0);
			verify(pstmt).setDouble(3, 0.8);
			verify(pstmt).setInt(4, 100);
		} catch (SQLException ignored) {}
	}

	@Test
	public void insertCvssScoreTest() {
		List<CvssScore> scores = new ArrayList<>();
		scores.add(new CvssScore("cve_id0", 10, 0.8, "impact0", 0.6));
		scores.add(new CvssScore("cve_id1", 1, 0.7, "impact1", 0.4));
		dbh.insertCvssScore(scores, conn);
		try {
			verify(pstmt, times(2*scores.size())).setString(anyInt(), any());
			verify(pstmt, times(2*scores.size())).setDouble(anyInt(), anyDouble());
			verify(pstmt, times(scores.size())).setInt(anyInt(), anyInt());
			verify(pstmt).setString(1, "cve_id0");
			verify(pstmt).setDouble(3, 0.7);
			verify(pstmt, times(scores.size())).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteCvssScoreTest() {
		try {
			int out = dbh.deleteCvssScore("cve", conn);
			verify(pstmt).setString(1, "cve");
			verify(pstmt).executeUpdate();
			assertEquals(0, out);
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteVulnTest() {
		int out = dbh.deleteVuln("cve");
		try {
			verify(pstmt).setString(1, "cve");
			verify(pstmt).executeUpdate();
			assertEquals(0, out);
		} catch (SQLException ignored) {}
	}

	@Test
	public void getActiveConnectionsTest() {
		HikariPoolMXBean bean = mock(HikariPoolMXBean.class);
		when(hds.getHikariPoolMXBean()).thenReturn(bean);
		when(bean.getActiveConnections()).thenReturn(5);
		int n = dbh.getActiveConnections();
		assertEquals(5, n);
	}

	@Test
	public void getIdleConnectionsTest() {
		HikariPoolMXBean bean = mock(HikariPoolMXBean.class);
		when(hds.getHikariPoolMXBean()).thenReturn(bean);
		when(bean.getIdleConnections()).thenReturn(6);
		int n = dbh.getIdleConnections();
		assertEquals(6, n);
	}

	@Test
	public void getTotalConnectionsTest() {
		HikariPoolMXBean bean = mock(HikariPoolMXBean.class);
		when(hds.getHikariPoolMXBean()).thenReturn(bean);
		when(bean.getTotalConnections()).thenReturn(11);
		int n = dbh.getTotalConnections();
		assertEquals(11, n);
	}

	@Test
	public void getConnectionStatusTest() {
		HikariPoolMXBean bean = mock(HikariPoolMXBean.class);
		when(hds.getHikariPoolMXBean()).thenReturn(bean);
		when(bean.getActiveConnections()).thenReturn(5);
		when(bean.getIdleConnections()).thenReturn(6);
		when(bean.getTotalConnections()).thenReturn(11);
		String connStatus = dbh.getConnectionStatus();
		assertEquals("[5,6]=11", connStatus);
	}

	@Test
	public void shutdownTest() {
		dbh.shutdown();
		verify(hds).close();
	}

	@Test
	public void getVulnerabilityIdListTest() {
		setResNextCount(3);
		setResInts("vuln_id", 3);
		List<Integer> ids = dbh.getVulnerabilityIdList("cve", conn);
		try {
			verify(pstmt).setString(1, "cve");
			verify(pstmt).executeQuery();
		} catch (SQLException ignored) {}
		assertEquals(3, ids.size());
		assertEquals(0, (int) ids.get(0));
		assertEquals(1337, (int) ids.get(1));
		assertEquals(2674, (int) ids.get(2));

		setResNextCount(0);
		ids = dbh.getVulnerabilityIdList("cve", conn);
		assertNotNull(ids);
		assertEquals(0, ids.size());
	}

	@Test
	public void getCvssSeverityLabelsTest() {
		setResNextCount(2);
		setResInts("cvss_severity_id", 2);
		setResStrings("cvss_severity_class", 2);
		Map<String, Integer> map = dbh.getCvssSeverityLabels();
		assertNotNull(map);
		assertEquals(2, map.size());
	}

	@Test
	public void getVdoLabelsTest() {
		setResNextCount(3);
		setResInts("vdo_label_id", 3);
		setResStrings("vdo_label_name", 3);
		Map<String, Integer> map = dbh.getVdoLabels();
		assertNotNull(map);
		assertEquals(3, map.size());
	}

	@Test
	public void getVdoNounGroups() {
		setResNextCount(4);
		setResInts("vdo_noun_group_id", 4);
		setResStrings("vdo_noun_group_name", 4);
		Map<String, Integer> map = dbh.getVdoNounGrpups();
		assertNotNull(map);
		assertEquals(4, map.size());
	}

	@Test
	public void getTableDataAsHashMapTest() {
		setResNextCount(3);
		setResStrings("stringfield", 3);
		setResInts("intfield", 3);
		try {
			Map<String, Integer> map = dbh.getTableDataAsHashMap("sentence", "intfield", "stringfield");
			assertNotNull(map);
			assertEquals(3, map.size());
			verify(pstmt).executeQuery("sentence");
			assertEquals(0, (int) map.get("stringfield0"));
			assertEquals(1337, (int) map.get("stringfield1"));
			assertEquals(2674, (int) map.get("stringfield2"));
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteNvipSourceUrlTest() {
		try {
			when(pstmt.executeUpdate()).thenReturn(4);
			int out = dbh.deleteNvipSourceUrl("url");
			assertEquals(4, out);
			verify(pstmt).setString(1, "url");

			when(pstmt.executeUpdate()).thenThrow(SQLException.class);
			out = dbh.deleteNvipSourceUrl("url2");
			assertEquals(0, out);
		} catch (SQLException ignored) {}
	}

	@Test
	public void flushNvipSourceUrlTest() {
		try {
			when(pstmt.executeUpdate()).thenReturn(37);
			int out = dbh.flushNvipSourceUrl();
			assertEquals(37, out);
		} catch (SQLException ignored) {}
	}

	@Test
	public void saveExploitsTest() {
		CompositeVulnerability vuln = new CompositeVulnerability(2468, "url", "cve", "platform", "pubdate", "moddate", "des", "domain");
		List<Exploit> exploits = new ArrayList<>();
		exploits.add(new Exploit("cve", 1357, "pubdate", "puburl", "des", "exp", "recdate"));
		Map<String, Vulnerability> map = new HashMap<>();
		map.put("diffcve", null);
		boolean success = dbh.saveExploits(vuln, exploits, map);
		assertFalse(success);
		map.clear();
		map.put("cve", new Vulnerability());
		success = dbh.saveExploits(vuln, exploits, map);
		assertTrue(success);
	}

	@Test
	public void insertExploitTest() {
		Exploit exp = new Exploit("cve", 1357, "pubdate", "puburl", "des", "exp", "recdate");
		try {
			boolean success = dbh.insertExploit(conn, exp);
			assertTrue(success);
			verify(pstmt, times(6)).setString(anyInt(), any());
			verify(pstmt, times(2)).setInt(anyInt(), anyInt());
			verify(pstmt).executeUpdate();
			verify(pstmt).setString(8, "recdate");
			verify(pstmt).setInt(3, 1357);
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteExploitsTest() {
		try {
			when(pstmt.executeUpdate()).thenReturn(5);
			int out = dbh.deleteExploits(conn, 1357);
			verify(pstmt).setInt(1, 1357);
			assertEquals(5, out);

			when(pstmt.executeUpdate()).thenThrow(SQLException.class);
			out = dbh.deleteExploits(conn, 13578);
			assertEquals(0, out);
		} catch (SQLException ignored) {}
	}

	@Test
	public void updateVulnerabilityDataFromCsv() {
		CompositeVulnerability vuln = new CompositeVulnerability(2468, "url", "cve", "platform", "pubdate", "moddate", "des", "domain");
		Map<String, Vulnerability> map = new HashMap<>();
		try {
			int out = dbh.updateVulnerabilityDataFromCsv(vuln, map, 1111);
			verify(pstmt, times(2)).setString(anyInt(), any());
			assertEquals(1, out);
		} catch (SQLException ignored) {}
	}

	@Test
	public void getMaxRunIdTest() {
		setResNextCount(1);
		try {
			when(res.getInt("run_id")).thenReturn(112358);
			assertEquals(112358, dbh.getMaxRunId());
		} catch (SQLException ignored) {}
	}

	@Test
	public void getVulnIdPatchSourceTest() {
		setResNextCount(3);
		setResStrings("source_url", 3);
		setResInts("vuln_id", 3);
		Map<String, Integer> out = dbh.getVulnIdPatchSource(1000);
		assertEquals(3, out.size());
		assertEquals(0, (int) out.get("source_url0"));
		assertEquals(1337, (int) out.get("source_url1"));
		assertEquals(2674, (int) out.get("source_url2"));
	}

	@Test
	public void getCveIdTest() {
		setResNextCount(1);
		setResStrings("cve_id", 1);
		try {
			String out = dbh.getCveId("8888");
			verify(pstmt).setInt(1, 8888);
			assertEquals("cve_id0", out);
		} catch (SQLException ignored) {}
	}

	@Test
	public void insertPatchCommitTest() {
		Date date = new Date();
		dbh.insertPatchCommit(2222, "url", "commitid", date, "commitmsg");
		try {
			verify(pstmt).setInt(1, 2222);
			verify(pstmt).setString(2, "url/commit/commitid");
			verify(pstmt).setDate(anyInt(), any());
			verify(pstmt).setString(4, "commitmsg");
			verify(pstmt).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void getEmailsRoleId() {
		setResNextCount(5);
		setResStrings("email", 5);
		setResStrings("first_name", 5);
		setResInts("role_id", 5);
		ArrayList<String> emails = dbh.getEmailsRoleId();
		String joiner = ";!;~;#&%:;!";
		assertEquals(5, emails.size());
		assertEquals(String.join(joiner, "email0", "first_name0", "0"), emails.get(0));
		assertEquals(String.join(joiner, "email4", "first_name4", "5348"), emails.get(4));
	}

	@Test
	public void getEmailRoleIdByUserTest() {
		String joiner = ";!;~;#&%:;!";
		String username = "uname";
		setResNextCount(1);
		setResStrings("email", 1);
		setResStrings("first_name", 1);
		setResInts("role_id", 1);
		ArrayList<String> out = dbh.getEmailRoleIdByUser(username);
		try {
			verify(pstmt).setString(1, username);
			assertEquals(1, out.size());
			assertEquals(String.join(joiner, "email0", "first_name0", "0"), out.get(0));
		} catch (SQLException ignored) {}
	}

	@Test
	public void getCVEByRunDateTest() {
		Date date = new java.sql.Date(2023, 1, 1);
		setResNextCount(3);
		setResStrings("cve_id", 3);
		setResStrings("description", 3);
		HashMap<String, String> out = dbh.getCVEByRunDate(date);
		assertEquals(3, out.size());
		assertEquals("description0", out.get("cve_id0"));
		assertEquals("description2", out.get("cve_id2"));
	}

	@Test
	public void getAllCveIdAndDescriptionsTest() {
		setResNextCount(3);
		setResStrings("cve_id", 3);
		setResStrings("description", 3);
		Map<String, String> out = dbh.getAllCveIdAndDescriptions();
		assertEquals(3, out.size());
		assertEquals("description0", out.get("cve_id0"));
		assertEquals("description2", out.get("cve_id2"));
	}

	@Test
	public void getVulnIdByCveIdTest() {
		try {
			setResNextCount(1);
			when(res.getInt("vuln_id")).thenReturn(1357);
			int out = dbh.getVulnIdByCveId("cve_id");
			verify(pstmt).setString(1, "cve_id");
			assertEquals(1357, out);
		} catch (SQLException ignored) {}
	}
}
