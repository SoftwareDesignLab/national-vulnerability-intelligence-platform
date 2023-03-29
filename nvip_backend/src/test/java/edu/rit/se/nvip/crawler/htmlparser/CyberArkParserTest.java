package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

public class CyberArkParserTest extends AbstractParserTest {

    @Test
    public void testCyberArkParser() {
        String html = safeReadHtml("src/test/resources/test-cyberark.html");
//        List<CompositeVulnerability> list = crawler.parseWebPage(
//                "https://amperecomputing.com/products/product-security",
//                html
//        );
//        assertEquals(6, list.size());
//        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-46892");
//        assertTrue(vuln.getDescription().contains("A Root complex is typically disabled during boot via the BIOS"));
//        assertEquals("2/14/2023", vuln.getPublishDate());
//        assertEquals("2/14/2023", vuln.getLastModifiedDate());
    }
}
