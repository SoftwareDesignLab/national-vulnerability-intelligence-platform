package edu.rit.se.nvip.crawler.htmlparser;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Vulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;

public class GenericCveParserTest {
	CveCrawler crawler = new CveCrawler(getProps());

	private MyProperties getProps() {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		return propertiesNvip;
	}

	private CompositeVulnerability getVulnerability(List<CompositeVulnerability> list, String cveID) {
		for (CompositeVulnerability vuln : list)
			if (vuln.getCveId().equalsIgnoreCase(cveID))
				return vuln;
		return null;
	}
	
	
	@Test
	public void testJenkins() throws IOException {

		String html = FileUtils.readFileToString(new File("src/test/resources/test-jenkins.html"));
		List<CompositeVulnerability> list = crawler.parseWebPage("jenkins", html);
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2017-1000355");
		boolean fine = vuln.getPlatform().contains("2.56");
		assertEquals(true, fine);
	}

	@Test
	public void testAndroidCom() throws MalformedURLException, IOException {
		String url = "https://source.android.com/security/bulletin/2017-09-01";
		String html = IOUtils.toString(new URL(url));
		List<CompositeVulnerability> list = crawler.parseWebPage(url, html);
		assertEquals(true, list.size() > 1);
	}
	
	@Test
	public void testOpenwall() throws IOException {

		String html = FileUtils.readFileToString(new File("src/test/resources/test-openwall.html"));
		List<CompositeVulnerability> list = crawler.parseWebPage("openwall", html);
		Vulnerability vuln = getVulnerability(list, "CVE-2015-4852");
		boolean fine = vuln.getDescription().contains("Oracle");
		assertEquals(true, fine);
	}	

}
