package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.FileUtils;
import org.junit.Test;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import static org.junit.Assert.assertEquals;

/**
 * Test Parser for VMWare Security Advisories Page
 * @author aep7128
 *
 * There is an older version of this page for earlier CVEs,
 * but CVE Descriptions aren't accuratly shown (ex. 4 CVEs have the same description,
 * then redirects to MITRE), we may want to ignore those cases for now. Just test on the recent web page layout
 *
 */
public class VMWareAdvisoriesTest {

	/**
	 * Test Parser for page that has 1 CVE
	 * @throws IOException
	 */
	@Test
	public void testVMWareAdvisoriesSingleCVE() throws IOException {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		CveCrawler crawler = new CveCrawler(propertiesNvip);
		String html = FileUtils.readFileToString(new File("src/test/resources/test-vmware-advisories-single-cve.html"), StandardCharsets.UTF_8);
		List<CompositeVulnerability> list = crawler.parseWebPage("https://www.vmware.com/security/advisories/VMSA-2023-0003.html", html);

		assertEquals(list.size(), 1);

		CompositeVulnerability vuln = list.get(0);

		assertEquals(vuln.getCveId(), "CVE-2023-20854");
		assertEquals(vuln.getDescription(), "VMware Workstation contains an arbitrary file deletion vulnerability. VMware has evaluated the severity of this issue to be in the Important severity range with a maximum CVSSv3 base score of 7.8.");
		assertEquals(vuln.getPublishDate(), "2023-02-02");
		assertEquals(vuln.getLastModifiedDate(), "2023-02-02");

	}

	/**
	 * Test Parser for page with multiple CVEs
	 * @throws IOException
	 */
	@Test
	public void testVMWareAdvisoriesMultiCVE() throws IOException {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		CveCrawler crawler = new CveCrawler(propertiesNvip);
		String html = FileUtils.readFileToString(new File("src/test/resources/test-vmware-advisories-multi-cve.html"), StandardCharsets.UTF_8);
		List<CompositeVulnerability> list = crawler.parseWebPage("https://www.vmware.com/security/advisories/VMSA-2023-0001.html", html);

		assertEquals(list.size(), 4);

		CompositeVulnerability vuln = list.get(0);

		assertEquals("CVE-2022-31706", vuln.getCveId());
		assertEquals("The vRealize Log Insight contains a Directory Traversal Vulnerability. VMware has evaluated the severity of this issue to be in the critical severity range with a maximum CVSSv3 base score of 9.8.", vuln.getDescription());
		assertEquals("2023-01-24", vuln.getPublishDate());
		assertEquals("2023-01-31", vuln.getLastModifiedDate());

	}

}
