package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Tests for Packet Storm Parser
 * @author aep7128
 */
public class PacketStormParserTest extends AbstractParserTest {

	PacketStormParser parser = new PacketStormParser("packetstorm");

	@Test
	public void testPacketStormFiles() {
		String html = safeReadHtml("src/test/resources/test-packetstorm-files.html");
		List<CompositeVulnerability> list = parser.parseWebPage("packetstorm", html);
		assertEquals(44, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2017-171069");
		assertNotNull(vuln);
		assertTrue(vuln.getDescription().contains("remote command execution vulnerability in Zivif webcams"));
		assertEquals("2020/06/16 00:00:00", vuln.getPublishDate());
	}

	@Test
	public void testPacketStormFiles2() {
		String html = safeReadHtml("src/test/resources/test-packetstorm-files-2.html");
		List<CompositeVulnerability> list = parser.parseWebPage("packetstorm", html);
		assertEquals(2, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-20705");
		assertNotNull(vuln);
		assertTrue(vuln.getDescription().contains("Cisco RV160, RV260, RV340, and RV345 Small Business Routers, allowing attackers to execute arbitrary commands"));
		assertEquals("2023/02/14 00:00:00", vuln.getPublishDate());
	}


	@Test
	public void testPacketStormPOC() {
		String html = safeReadHtml("src/test/resources/test-packetstorm-poc-files.html");
		List<CompositeVulnerability> list = parser.parseWebPage("packetstorm", html);
		assertEquals(8, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2020-15956");
		assertNotNull(vuln);
		assertTrue(vuln.getDescription().contains("ACTi NVR3 Standard"));
		assertEquals("2020/08/06 00:00:00", vuln.getPublishDate());

	}

	@Test
	public void testPacketStormAdvisory() {
		String html = safeReadHtml("src/test/resources/test-packetstorm-advisory.html");
		List<CompositeVulnerability> list = parser.parseWebPage("packetstorm", html);
		assertEquals(78, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2020-16008");
		assertNotNull(vuln);
		assertTrue(vuln.getDescription().contains("Multiple vulnerabilities have been found in Chromium"));
		assertEquals("2020/11/11 00:00:00", vuln.getPublishDate());
	}

	@Test
	public void testPacketStormCVEDetail() {
		String html = safeReadHtml("src/test/resources/test-packetstorm-cvedetail.html");
		List<CompositeVulnerability> list = parser.parseWebPage("packetstorm.html", html);
		assertEquals(2, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2018-4109");
		assertNotNull(vuln);
		assertTrue(vuln.getDescription().contains("Phrack Viewer Discretion Advised"));
		assertEquals("2018/10/30 00:00:00", vuln.getPublishDate());
	}

	@Test
	public void testPacketStormDaily() {
		String html = safeReadHtml("src/test/resources/test-packetstorm-daily.html");
		List<CompositeVulnerability> list = new PacketStormParser("packetstorm").parseWebPage("packetstorm", html);
		assertEquals(31, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2021-21425");
		assertNotNull(vuln);
		assertTrue(vuln.getDescription().contains("Unauthenticated users can execute a terminal command"));
		assertEquals("2021/05/04 00:00:00", vuln.getPublishDate());
	}

}
