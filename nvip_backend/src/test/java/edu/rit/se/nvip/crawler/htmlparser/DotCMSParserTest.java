package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;
import static junit.framework.TestCase.assertEquals;

public class DotCMSParserTest extends AbstractParserTest {


    // CVE: (link)
    @Test
    public void testDotCMSParser1() {
        String html = safeReadHtml("src/test/resources/test-dotcms1.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.dotcms.com/security/SI-54",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2020-6754");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("dotCMS fails to normalize the URI string when checking if a user should have access"));
        assertEquals("Jan 9, 2020, 10:30:00 AM", vuln.getPublishDate());
        assertEquals("Jan 9, 2020, 10:30:00 AM", vuln.getLastModifiedDate());
    }

    // CVE standalone id found in references
    @Test
    public void testDotCMSParser2() {
        String html = safeReadHtml("src/test/resources/test-dotcms2.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.dotcms.com/security/SI-67",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-45783");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("An authenticated directory traversal vulnerability in dotCMS API can lead to RCE"));
        assertEquals("Dec 15, 2022, 11:15:00 AM", vuln.getPublishDate());
        assertEquals("Dec 15, 2022, 11:15:00 AM", vuln.getLastModifiedDate());
    }

    // no CVE referenced on page
    @Test
    public void testDotCMSParserNone() {
        String html = safeReadHtml("src/test/resources/test-dotcms-none.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.dotcms.com/security/SI-53",
                html
        );
        assertEquals(0, list.size());
    }

}
