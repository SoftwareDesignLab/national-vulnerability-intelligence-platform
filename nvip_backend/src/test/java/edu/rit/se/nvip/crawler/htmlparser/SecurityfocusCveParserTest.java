package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class SecurityfocusCveParserTest extends AbstractParserTest {

	@Test
	public void testSecurityfocusParser(){
		String html = safeReadHtml("src/test/resources/test-securityfocus.html");
		List<CompositeVulnerability> list = new SecurityfocusCveParser("securityfocus").parseWebPage("securityfocus", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2015-3269", vuln.getCveId());
		assertEquals("2015/08/18 00:00:00", vuln.getPublishDate());
	}

}
