package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class VMWareParserTest extends AbstractParserTest {

    @Test
    public void testVMWareAdvisories() {
        String html = safeReadHtml("src/test/resources/test-vmware.html");
        List<CompositeVulnerability> list = new VMWareParser("vmware").parseWebPage("vmware", html);
        assertEquals(5,list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2007-4965");
        assertNotNull(vuln);
        assertEquals("2008/02/04 00:00:00", vuln.getPublishDate());
    }

}
