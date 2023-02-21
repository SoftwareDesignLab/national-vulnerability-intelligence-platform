package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;
import java.util.List;

import static org.junit.Assert.*;

public class KbCertCveParserTest extends AbstractParserTest {

    @Test
    public void testKbCertMultipleCVE() {
        String html = safeReadHtml("src/test/resources/test-kb-cert.html");
        List<CompositeVulnerability> list = new KbCertCveParser("kb.cert").parseWebPage("kb.cert", html);
        assertEquals(2, list.size());

        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-4498");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("HTTP Basic Authentication mode"));
        assertFalse(vuln.getDescription().contains("susceptible to a side-channel attack"));

        vuln = getVulnerability(list, "CVE-2022-4499");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("susceptible to a side-channel attack"));
        assertFalse(vuln.getDescription().contains("HTTP Basic Authentication mode"));
    }

    @Test
    public void testKbCertSingleCVE() {
        String html = safeReadHtml("src/test/resources/test-kb-cert-single.html");
        List<CompositeVulnerability> list = new KbCertCveParser("kb.cert").parseWebPage("kb.cert", html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2021-33164");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("access and validation of the SMRAM"));
        assertEquals("2022/11/08 00:00:00", vuln.getPublishDate());
    }
}