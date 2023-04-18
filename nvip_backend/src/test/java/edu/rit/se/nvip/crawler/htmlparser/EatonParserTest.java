package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.QuickCveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class EatonParserTest extends AbstractParserTest {

    @Test
    public void testEatonDownloadAndParse() {
        String html = safeReadHtml("src/test/resources/test-eaton.html");
//        String html = QuickCveCrawler.getContentFromDynamicPage("https://www.eaton.com/content/dam/eaton/company/news-insights/cybersecurity/security-bulletins/wibu-systems-ag-codemeter-vulnerabilities-eaton-security-bulletin.pdf", null);
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.eaton.com/content/dam/eaton/company/news-insights/cybersecurity/security-bulletins/wibu-systems-ag-codemeter-vulnerabilities-eaton-security-bulletin.pdf",
                html
        );
        assertEquals(6, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2020-14509");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("CodeMeter Runtime for protecting the codes and managing the licenses"));
        assertEquals("10/5/2020", vuln.getPublishDate());
        assertEquals("03/04/2021", vuln.getLastModifiedDate());
    }
}
