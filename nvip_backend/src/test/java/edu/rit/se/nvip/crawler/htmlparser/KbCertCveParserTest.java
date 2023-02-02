package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class KbCertCveParserTest {

    @Test
    void testKbCert() {
        String html = null;
        try {
            html = FileUtils.readFileToString(new File("src/test/resources/test-kb-cert.html"), "UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
        List<CompositeVulnerability> list = new KbCertCveParser("kb.cert").parseWebPage("kb.cert", html);
        assertEquals(2, list.size());
        for (CompositeVulnerability vuln : list) {
            if (vuln.getCveId().equals("CVE-2022-4498")) {
                assertTrue(vuln.getDescription().contains("HTTP Basic Authentication mode"));
                assertFalse(vuln.getDescription().contains("susceptible to a side-channel attack"));
            } else if (vuln.getCveId().equals("CVE-2022-4499")) {
                assertTrue(vuln.getDescription().contains("susceptible to a side-channel attack"));
                assertFalse(vuln.getDescription().contains("HTTP Basic Authentication mode"));
            } else {
                fail();
            }
        }
    }
}