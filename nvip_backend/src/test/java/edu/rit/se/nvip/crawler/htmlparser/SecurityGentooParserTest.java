package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SecurityGentooParserTest extends AbstractParserTest {


	@Test
	public void testSecurityGentooSingle() {
		String html = safeReadHtml("src/test/resources/test-security-gentoo-single.html");
		List<CompositeVulnerability> list = new SecurityGentooParser("gentoo").parseWebPage("security.gentoo", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2005-0453", vuln.getCveId());
		assertEquals("2005/02/15 00:00:00", vuln.getPublishDate());
		assertEquals("lighttpd uses file extensions to determine which elements are programs that should be executed and which are static pages that should be sent as-is. By appending %00 to the filename, you can evade the extension detection mechanism while still accessing the file. A remote attacker could send specific queries and access the source of scripts that should have been executed as CGI or FastCGI applications.",
				vuln.getDescription());
	}

	@Test
	public void testSecurityGentooMulti() {
		String html = safeReadHtml("src/test/resources/test-security-gentoo-multi.html");
		List<CompositeVulnerability> list = new SecurityGentooParser("gentoo").parseWebPage("security.gentoo", html);
		assertEquals(3, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-3171");
		assertNotNull(vuln);
		assertEquals("2023/01/11 00:00:00", vuln.getPublishDate());
		assertEquals("Inputs containing multiple instances of non-repeated embedded messages with repeated or unknown fields causes objects to be converted back and forth between mutable and immutable forms, resulting in potentially long garbage collection pauses. Crafted input can trigger a denial of service via long garbage collection pauses.",
				vuln.getDescription());
	}
}
