package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.FileUtils;
import org.junit.Test;
import java.io.File;
import java.io.IOException;
import java.util.List;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test Parser for VMWare Security Advisories Page
 * @author aep7128
 *
 * TODO: There is an older version of this page for older CVEs,
 * 	but CVE Descriptions aren't accuratly shown (ex. 4 CVEs have the same description,
 * 	then redirects to MITRE), we may want to ignore those cases for now. Just test on the recent web page layout
 *
 */
public class VMWareAdvisoriesTest {

	@Test
	public void testVMWareAdvisories() throws IOException {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		CveCrawler crawler = new CveCrawler(propertiesNvip);
		String html = FileUtils.readFileToString(new File("src/test/resources/test-vmware-advisories.html"));
		List<CompositeVulnerability> list = crawler.parseWebPage("https://www.vmware.com/security/advisories/VMSA-2023-0003.html", html);

		assertEquals(list.size(), 1);

		CompositeVulnerability vuln = list.get(0);

		assertEquals(vuln.getCveId(), "CVE-2023-20854");
		assertEquals(vuln.getDescription(), "VMware Workstation contains an arbitrary file deletion vulnerability. VMware has evaluated the severity of this issue to be in the Important severity range with a maximum CVSSv3 base score of 7.8.");
		assertEquals(vuln.getPublishDate(), "2023-02-02");
		assertEquals(vuln.getLastModifiedDate(), "2023-02-02");

	}

}
