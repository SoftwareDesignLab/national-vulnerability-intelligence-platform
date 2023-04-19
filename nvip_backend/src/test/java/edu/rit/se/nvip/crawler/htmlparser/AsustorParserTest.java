package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;
import static junit.framework.TestCase.assertEquals;

public class AsustorParserTest extends AbstractParserTest {

    @Test
    public void testAsustorParserNone() {
        String html = safeReadHtml("src/test/resources/test-asustor-none.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.asustor.com/security/security_advisory_detail?id=9",
                html
        );
        assertEquals(0, list.size());
    }

    @Test
    public void testAsustorParserSingle() {
        String html = safeReadHtml("src/test/resources/test-asustor-single.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.asustor.com/security/security_advisory_detail?id=4",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-0847");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("A flaw was found in the way the \"flags\" member of the new pipe buffer structure was lacking prope"));
        assertEquals("2022-03-11", vuln.getPublishDate());
        assertEquals("2022-07-07", vuln.getLastModifiedDate());
    }

    @Test
    public void testAsustorParserMultiple() {
        String html = safeReadHtml("src/test/resources/test-asustor-multiple.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.asustor.com/security/security_advisory_detail?id=20",
                html
        );
        assertEquals(4, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-4304");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE."));
        assertFalse(vuln.getDescription().contains("This could be exploited by an attacker who has the ability to supply malicious PEM files for parsing to achieve a denial of service attack."));
        assertEquals("2023-03-31", vuln.getPublishDate());
        assertEquals("2023-03-31", vuln.getLastModifiedDate());
    }


}
