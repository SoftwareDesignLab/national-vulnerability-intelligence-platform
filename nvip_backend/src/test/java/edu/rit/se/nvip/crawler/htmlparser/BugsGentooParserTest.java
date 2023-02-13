package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class BugsGentooParserTest extends AbstractParserTest {

    @Test
    public void testBugsGentoo() {
        String html = safeReadHtml("src/test/resources/test-bugsgentoo.html");
        List<CompositeVulnerability> list = new BugsGentooParser("gentoo").parseWebPage("bugs.gentoo", html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2010-4563", vuln.getCveId());
        assertEquals("2012/02/03 04:34:34", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("ICMPv6 Echo"));
    }
}