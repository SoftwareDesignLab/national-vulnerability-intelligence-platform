package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class SeclistsParserTest extends AbstractParserTest {

	@Test
	public void testSeclistsParser0() {
		String html = safeReadHtml("src/test/resources/test-seclist-cvedetail.html");
		List<CompositeVulnerability> list = new SeclistsParser("seclists").parseWebPage("seclists", html);
		assertEquals(1, list.size());
		assertEquals("CVE-2016-0763", list.get(0).getCveId());
		assertTrue(list.get(0).getDescription().contains("ResourceLinkFactory.setGlobalContext() is a public method"));
		assertFalse(list.get(0).getDescription().contains("Bugtraq"));
		assertEquals("2016/02/22 11:23:30", list.get(0).getPublishDate());
	}

	@Test
	public void testSeclistsParser1() {
		String html = safeReadHtml("src/test/resources/test-seclist-date.html");
		List<CompositeVulnerability> list = new SeclistsParser("seclists").parseWebPage("seclists", html);
		assertEquals(1, list.size());
		assertEquals("CVE-2015-2807", list.get(0).getCveId());
		assertTrue(list.get(0).getDescription().contains("Publicly exploitable XSS in WordPress plugin"));
		assertFalse(list.get(0).getDescription().contains("Nmap Security"));
		assertEquals("2015/08/26 15:15:14", list.get(0).getPublishDate());
	}

}
