package edu.rit.se.nvip.crawler.htmlparser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import java.util.List;

import org.junit.Test;

import edu.rit.se.nvip.model.CompositeVulnerability;

public class BugzillaParserTest extends AbstractParserTest {

	@Test
	public void testBugzilla() {
		String html = safeReadHtml("src/test/resources/test-bugzilla-cvedetail.html");
		List<CompositeVulnerability> list = new BugzillaParser("bugzilla").parseWebPage("bugzilla", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2013-1747", vuln.getCveId());
		assertEquals("2020/10/31 00:00:00", vuln.getPublishDate());
		assertTrue(vuln.getDescription().contains("DoS (assertion failure, crash) via a KICK command"));
	}
}
