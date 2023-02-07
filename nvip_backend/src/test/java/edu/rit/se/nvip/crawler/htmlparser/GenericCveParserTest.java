package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Vulnerability;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.*;

public class GenericCveParserTest extends AbstractParserTest {

	GenericCveParser parser = new GenericCveParser("nat_available");
	
	@Test
	public void testJenkins() {
		String html = safeReadHtml("src/test/resources/test-jenkins.html");
		List<CompositeVulnerability> list = parser.parseWebPage("jenkins", html);
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2017-1000355");
		assertNotNull(vuln);
		boolean fine = vuln.getPlatform().contains("2.56");
		assertTrue(fine);
	}

	@Test
	public void testAndroidCom() {

		String url = "https://source.android.com/security/bulletin/2017-09-01";
		String html = null;
		try {
			html = IOUtils.toString(new URL(url), StandardCharsets.UTF_8);
		} catch (IOException e) {
			e.printStackTrace();
			fail();
		}
		List<CompositeVulnerability> list = parser.parseWebPage(url, html);
		assertTrue(list.size() > 1);
	}
	
	@Test
	public void testOpenwall() {
		String html = safeReadHtml("src/test/resources/test-openwall.html");
		List<CompositeVulnerability> list = parser.parseWebPage("openwall", html);
		Vulnerability vuln = getVulnerability(list, "CVE-2015-4852");
		assertNotNull(vuln);
		boolean fine = vuln.getDescription().contains("Oracle");
		assertTrue(fine);
	}	

}
