package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class CyberArkParserTest extends AbstractParserTest {

    @Test
    public void testCyberArkRootParser() {
        String html = safeReadHtml("src/test/resources/test-cyberark.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://labs.cyberark.com/cyberark-labs-security-advisories/",
                html
        );
        assertEquals(132, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-23774");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Docker"));
        assertEquals("25-Jan-22", vuln.getPublishDate());
        assertEquals("25-Jan-22", vuln.getLastModifiedDate());
    }
}
