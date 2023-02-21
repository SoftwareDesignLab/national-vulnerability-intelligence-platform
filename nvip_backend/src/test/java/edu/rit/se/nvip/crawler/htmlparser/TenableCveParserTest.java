package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class TenableCveParserTest extends AbstractParserTest {
	public static final String TEST_DESCRIPTION = "A Missing Authorization vulnerability in of SUSE Rancher allows authenticated user to create an unauthorized shell pod and kubectl access in the local cluster This issue affects: SUSE Rancher Rancher versions prior to 2.5.17; Rancher versions prior to 2.6.10; Rancher versions prior to 2.7.1.";
	@Test
	public void testTenableCveParser0() {
		String html = safeReadHtml("src/test/resources/test-tenable-newest.html");
		List<CompositeVulnerability> list = new TenableCveParser("tenable").parseWebPage("tenable.com/cve/newest", html);
		assertEquals(50, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-21953");
		assertNotNull(vuln);
		assertEquals(TEST_DESCRIPTION, vuln.getDescription());
	}

	@Test
	public void testTenableCveParser1() {
		String html = safeReadHtml("src/test/resources/test-tenable.html");
		List<CompositeVulnerability> list = new TenableCveParser("tenable").parseWebPage("tenable", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2022-21953", vuln.getCveId());
		assertEquals("2023/02/07 00:00:00", vuln.getPublishDate());
		assertEquals(TEST_DESCRIPTION, vuln.getDescription());
	}

}
