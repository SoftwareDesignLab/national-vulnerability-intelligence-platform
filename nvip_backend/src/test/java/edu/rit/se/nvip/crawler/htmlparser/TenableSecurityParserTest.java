package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class TenableSecurityParserTest extends AbstractParserTest {

    @Test
    public void testTenableSecurityParser0() {
        String html = safeReadHtml("src/test/resources/test-tenable-security.html");
        List<CompositeVulnerability> list = new TenableSecurityParser("tenable").parseWebPage("tenable", html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-0587", vuln.getCveId());
        assertEquals("2023/01/30 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("A file upload vulnerability in exists in Trend Micro Apex One"));
        assertFalse(vuln.getDescription().contains("View More Research Advisories"));
    }

    @Test
    public void testTenableSecurityParser1() {
        String html = safeReadHtml("src/test/resources/test-tenable-security-2.html");
        List<CompositeVulnerability> list = new TenableSecurityParser("tenable").parseWebPage("tenable", html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-4390", vuln.getCveId());
        assertEquals("2022/12/02 00:00:00", vuln.getPublishDate());
        assertEquals("2022/12/09 00:00:00", vuln.getLastModifiedDate());
        assertTrue(vuln.getDescription().contains("A network misconfiguration is present"));
        assertFalse(vuln.getDescription().contains("View More Research Advisories"));
    }
}