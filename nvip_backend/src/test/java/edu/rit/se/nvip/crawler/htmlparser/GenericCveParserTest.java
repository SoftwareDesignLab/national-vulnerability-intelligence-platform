package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Vulnerability;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class GenericCveParserTest {

	GenericCveParser parser = new GenericCveParser("nat_available");

	private CompositeVulnerability getVulnerability(List<CompositeVulnerability> list, String cveID) {
		for (CompositeVulnerability vuln : list)
			if (vuln.getCveId().equalsIgnoreCase(cveID))
				return vuln;
		return null;
	}
	
	
	@Test
	public void testJenkins() {
		String html = null;
		try {
			html = FileUtils.readFileToString(new File("src/test/resources/test-jenkins.html"), StandardCharsets.UTF_8);
		} catch (IOException e) {
			e.printStackTrace();
			fail();
		}
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
		String html = null;
		try {
			html = FileUtils.readFileToString(new File("src/test/resources/test-openwall.html"), StandardCharsets.UTF_8);
		} catch (IOException e) {
			e.printStackTrace();
			fail();
		}
		List<CompositeVulnerability> list = parser.parseWebPage("openwall", html);
		Vulnerability vuln = getVulnerability(list, "CVE-2015-4852");
		assertNotNull(vuln);
		boolean fine = vuln.getDescription().contains("Oracle");
		assertTrue(fine);
	}	

}
