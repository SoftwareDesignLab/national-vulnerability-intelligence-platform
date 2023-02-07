package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class SecurityTrackerParserTest extends AbstractParserTest {

	@Test
	public void testSecurityTracker() {
		String html = safeReadHtml("src/test/resources/test-securitytracker-cvedetail.html");
		List<CompositeVulnerability> list =  new SecurityTrackerParser("securitytracker").parseWebPage("securitytracker", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2016-2183", vuln.getCveId());
		assertEquals("2017/08/11 00:00:00", vuln.getPublishDate());
		assertTrue(vuln.getDescription().contains("A vulnerability was reported in OpenSSL"));
		assertFalse(vuln.getDescription().contains("Disclosure of system information"));
	}
}
