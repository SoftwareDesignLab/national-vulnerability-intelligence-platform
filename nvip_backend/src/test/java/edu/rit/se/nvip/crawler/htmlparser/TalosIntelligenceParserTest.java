package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class TalosIntelligenceParserTest extends AbstractParserTest {

	@Test
	public void testTalosIntelligence() {
		String html = safeReadHtml("src/test/resources/test-talos.html");
		List<CompositeVulnerability> list = new TalosIntelligenceParser("talosintelligence").parseWebPage("talosintelligence", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2022-40224", vuln.getCveId());
		assertEquals("2022/10/14 00:00:00", vuln.getPublishDate());
		assertTrue(vuln.getDescription().contains("A denial of service vulnerability exists"));
		assertTrue(vuln.getDescription().contains("An HTTP request to port 443"));
		assertFalse(vuln.getDescription().contains("Discovered by Patrick"));
	}


	@Test
	public void testTalosIntelligence2() {
		String html = safeReadHtml("src/test/resources/test-talos-2.html");
		List<CompositeVulnerability> list = new TalosIntelligenceParser("talosintelligence").parseWebPage("talosintelligence", html);
		assertEquals(3, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-41313");
		assertNotNull(vuln);
		assertEquals("2022/10/14 00:00:00", vuln.getPublishDate());
		assertTrue(vuln.getDescription().contains("The SDS-3008 is an 8-port smart Ethernet switch"));
		assertTrue(vuln.getDescription().contains("A stored cross-site scripting vulnerability"));
		assertFalse(vuln.getDescription().contains("The following input in"));
	}

}
