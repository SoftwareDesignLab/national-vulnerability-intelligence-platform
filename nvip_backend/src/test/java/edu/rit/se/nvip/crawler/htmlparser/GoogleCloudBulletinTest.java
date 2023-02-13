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

        assertEquals(list.size(), 1);

    }

}
