package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class VMWareAdvisoriesTest extends AbstractParserTest {

	@Test
	public void testVMWareAdvisories() {
		String html =safeReadHtml("src/test/resources/test-vmware-advisories.html");
		List<CompositeVulnerability> list = new VMWareAdvisoriesParser("vmware").parseWebPage("vmware", html);
		assertEquals(8, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2006-5752");
		assertNotNull(vuln);
		assertEquals("2009/08/20 00:00:00", vuln.getPublishDate());
		assertTrue(vuln.getDescription().contains("Several flaws were discovered"));
		assertFalse(vuln.getDescription().contains("Build, run, manage, connect"));

	}
}
