package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static junit.framework.TestCase.assertEquals;

public class BoschSecurityParserTest {

    @Test
    public void testBoschSecurity() throws IOException{

        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

        String html = FileUtils.readFileToString(new File("src/test/resources/test-bosch-security.html"), StandardCharsets.US_ASCII);
        List<CompositeVulnerability> list = new CveCrawler(propertiesNvip).parseWebPage("bosch", html);

        CompositeVulnerability vuln1 = list.get(0);
        CompositeVulnerability vuln2 = list.get(1);

        assertEquals("Expected CVE-2014-3507, but got: ", "CVE-2014-3507", vuln1.getCveId());
        assertEquals("Expected CVE-2018-21028, but got: ", "CVE-2018-21028", vuln2.getCveId());

        assertEquals("Memory leak in d1_both.c in the DTLS implementation in OpenSSL 0.9.8 before 0.9.8zb, 1.0.0 before 1.0.0n, and 1.0.1 before 1.0.1i allows remote attackers to cause a denial of service (memory consumption) via zero-length DTLS fragments that trigger improper handling of the return value of a certain insert function. ",
                vuln1.getDescription());
        assertEquals("Boa through 0.94.14rc21 allows remote attackers to trigger a memory leak because of missing calls to the free function. ",
                vuln2.getDescription());
        //assertEquals("Expected 10, but got: " + list.size(),96, list.size());
    }
}
