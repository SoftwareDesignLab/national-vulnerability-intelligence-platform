package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BugsGentooParserTest {

    @Test
    void testBugsGentoo() {
        String html = null;
        try {
            html = FileUtils.readFileToString(new File("src/test/resources/test-bugsgentoo.html"), "UTF-8");

        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
        List<CompositeVulnerability> list = new BugsGentooParser("gentoo").parseWebPage("bugs.gentoo", html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2010-4563", vuln.getCveId());
        assertEquals("2012/02/03 04:34:34", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("ICMPv6 Echo"));
    }
}