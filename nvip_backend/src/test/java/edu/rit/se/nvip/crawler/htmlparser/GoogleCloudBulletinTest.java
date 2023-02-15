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
import static junit.framework.TestCase.assertTrue;

/**
 * Test for Google Cloud Bulletin Parser
 * @author aep7128
 */
public class GoogleCloudBulletinTest extends AbstractParserTest {

    @Test
    public void testGoogleCloudsecurityBulletinParser() throws IOException {

        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

        CveCrawler crawler = new CveCrawler(propertiesNvip);
        String html = FileUtils.readFileToString(new File("src/test/resources/test-google-cloud-bulletin.html"), StandardCharsets.US_ASCII);
        List<CompositeVulnerability> list = crawler.parseWebPage("https://cloud.google.com/support/bulletins", html);

        assertEquals(52, list.size());

        CompositeVulnerability vuln1 = list.get(0);
        CompositeVulnerability vuln6 = list.get(5);

        assertEquals("CVE-2022-3786", vuln1.getCveId());
        assertEquals("2023-01-11", vuln1.getPublishDate());
        assertEquals("2023-01-11", vuln1.getLastModifiedDate());
        assertTrue(vuln1.getDescription().contains("OpenSSL v3.0.6 that can potentially cause a crash."));
        assertEquals("CVE-2022-2588", vuln6.getCveId());
        assertEquals("2022-11-09", vuln6.getPublishDate());
        assertEquals("2023-01-19", vuln6.getLastModifiedDate());
        assertTrue(vuln6.getDescription().contains("Linux kernel that can lead to a full container break out to root on the node."));

    }

}
