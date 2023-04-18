package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;
import static junit.framework.TestCase.assertEquals;

public class AnquankeParserTest extends AbstractParserTest {

    @Test
    public void testAnquankeParser() {
        String html = safeReadHtml("src/test/resources/test-anquanke.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.anquanke.com/post/id/210200",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2020-5764");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("安卓MX Player播放器路径穿越和代码执行漏洞"));
        assertEquals("2020-07-10 16:30:16", vuln.getPublishDate());
        assertEquals("2020-07-10 16:30:16", vuln.getLastModifiedDate());
    }
}
