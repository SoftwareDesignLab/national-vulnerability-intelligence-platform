package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class DragosParserTest extends AbstractParserTest {

    // test a dragos page where there are no CVE IDs available
    @Test
    public void testDragosNA() {
        String html = safeReadHtml("src/test/resources/test-dragos-na.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.dragos.com/advisory/yokogawa-centum-vp-dcs-his/",
                html
        );
        assertEquals(0, list.size());
    }

    @Test
    public void testDragosMultiple() {
        String html = safeReadHtml("src/test/resources/test-dragos-mult.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.dragos.com/advisory/automation-directs-directlogic-06-plc-c-more-ea9-hmi-and-ecom-ethernet-module/",
                html
        );
        assertEquals(4, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-2006");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Automation Direct’s DirectLogic 06 PLC"));
        assertEquals("05/31/2022", vuln.getPublishDate());
        assertEquals("05/31/2022", vuln.getLastModifiedDate());
    }

}
