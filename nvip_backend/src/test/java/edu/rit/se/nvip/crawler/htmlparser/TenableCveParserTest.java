package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class TenableCveParserTest {
	@Test
	public void testTenableParser() {

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		try {
			String link = "https://www.tenable.com/cve/newest";
			String html = IOUtils.toString(new URL(link), StandardCharsets.UTF_8);
			List<CompositeVulnerability> list = new CveCrawler(propertiesNvip).parseWebPage(link, html);
			assertTrue(list.size() > 0);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
