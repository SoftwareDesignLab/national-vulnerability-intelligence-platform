package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class SambaParserTest extends AbstractParserTest {

    @Test
    public void testSambaParser() {
        String html = safeReadHtml("src/test/resources/test-samba.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.samba.org/samba/security/CVE-2022-38023.html",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-38023");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("The weakness on NetLogon Secure channel is that the secure checksum"));
    }
}
