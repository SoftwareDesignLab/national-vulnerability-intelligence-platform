package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

public class ZeroDaysParserTest extends AbstractParserTest {

    @Test
    public void testZeroDays() {
        String html = safeReadHtml("src/test/resources/test-zeroday.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://cybersecurityworks.com/zerodays/cve-2022-28291-sensitive-information-disclosure-in-tenable-nessus-scanner.html",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-28291", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("An authenticated user with debug privileges can retrieve stored Nessus policy"));
        assertEquals("May 2, 2022", vuln.getPublishDate());
        assertEquals("October 18, 2022", vuln.getLastModifiedDate());
    }

}
