package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class SecurityGentooParserTest extends AbstractParserTest {


	@Test
	public void testSecurityGentoo() {
		String html = safeReadHtml("src/test/resources/test-gentoo-cvedetail.html");
		List<CompositeVulnerability> list = new SecurityGentooParser("gentoo").parseWebPage("gentoo", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2005-0453", vuln.getCveId());
		assertEquals("2005/02/15 00:00:00", vuln.getPublishDate());
		assertTrue(vuln.getDescription().contains("By appending %00 to the filename, you can evade"));
		assertFalse(vuln.getDescription().contains("flexible web-server"));
	}
}
