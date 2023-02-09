package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;
import java.util.List;

import static org.junit.Assert.*;

public class KbCertCveParserTest extends AbstractParserTest {

    @Test
    public void testKbCert() {
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
}