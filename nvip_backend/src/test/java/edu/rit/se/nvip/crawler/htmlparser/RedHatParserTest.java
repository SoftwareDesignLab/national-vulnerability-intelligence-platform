package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class RedHatParserTest extends AbstractParserTest {

	String TEST_DESCRIPTION_CVE = "Usage of temporary files with insecure permissions by the Apache James server allows an attacker with local access to access private user data in transit. Vulnerable components includes the SMTP stack and IMAP APPEND command. This issue affects Apache James server version 3.7.2 and prior versions.";
	@Test
	public void testRedHat() {
		RedHatParser parser = new RedHatParser("redhat");
		String html = safeReadHtml("src/test/resources/test-redhat-cve.html");
		List<CompositeVulnerability> list = parser.parseWebPage("redhat", html);

		assertEquals(1, list.size());
		CompositeVulnerability sample = list.get(0);
		assertEquals("CVE-2022-45935", sample.getCveId());
		assertEquals(TEST_DESCRIPTION_CVE, sample.getDescription());
	}
}
