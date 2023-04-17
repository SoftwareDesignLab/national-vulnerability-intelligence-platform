package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class LibreOfficeParserTest extends AbstractParserTest {

    @Test
    public void testLibreOfficeParser() {
        String html = safeReadHtml("src/test/resources/test-libreoffice.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.libreoffice.org/about-us/security/advisories/cve-2019-9850/",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2019-9850");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("to block calling LibreLogo from script event handers."));
        assertEquals("August 15, 2019", vuln.getPublishDate());
    }

}
