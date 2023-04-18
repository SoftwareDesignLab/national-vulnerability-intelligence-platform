package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class PandoraFMSParserTest extends AbstractParserTest {
    @Test
    public void testPandoraFMSParser() {
        String html = safeReadHtml("src/test/resources/test-pandorafms.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/",
                html
        );
        assertEquals(65, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2023-24517");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Remote Code Execution via Unrestricted File Upload"));
        assertEquals("21 Feb 2023", vuln.getPublishDate());
    }
}
