package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class SeclistsParserTest extends AbstractParserTest {

	@Test
	public void testSeclistsParser0() {
		String html = safeReadHtml("src/test/resources/test-seclist.html");
		List<CompositeVulnerability> list = new SeclistsParser("seclists").parseWebPage("seclists", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2016-0763", vuln.getCveId());
		assertTrue(vuln.getDescription().contains("ResourceLinkFactory.setGlobalContext() is a public method"));
		assertFalse(vuln.getDescription().contains("Bugtraq"));
		assertEquals("2016/02/22 11:23:30", vuln.getPublishDate());
	}

	@Test
	public void testSeclistsParser1() {
		String html = safeReadHtml("src/test/resources/test-seclist-2.html");
		List<CompositeVulnerability> list = new SeclistsParser("seclists").parseWebPage("seclists", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2015-2807", vuln.getCveId());
		assertTrue(vuln.getDescription().contains("Publicly exploitable XSS in WordPress plugin"));
		assertFalse(vuln.getDescription().contains("Nmap Security"));
		assertEquals("2015/08/26 15:15:14", vuln.getPublishDate());
	}

	@Test
	public void testSecListsParser2() {
		String html = safeReadHtml("src/test/resources/test-seclist-3.html");
		List<CompositeVulnerability> list = new SeclistsParser("seclists").parseWebPage("seclists", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2022-44877", vuln.getCveId());
		assertTrue(vuln.getDescription().contains("Bash commands can be run"));
		assertFalse(vuln.getDescription().contains("mailing list archives"));
		assertEquals("2023/01/03 19:20:15", vuln.getPublishDate());
	}

}
