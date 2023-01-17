package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class PacketStormParserTest {

	@Test
	public void testPacketStorm() throws IOException {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		CveCrawler crawler = new CveCrawler(propertiesNvip);

		// test parsing of CVEs from different packetstorm pages
		String html = FileUtils.readFileToString(new File("src/test/resources/test-packetstorm-files.html"), StandardCharsets.UTF_8);
		List<CompositeVulnerability> list = crawler.parseWebPage("packetstorm", html);
		boolean fine = list.size() > 0;

		html = FileUtils.readFileToString(new File("src/test/resources/test-packetstorm-poc-files.html"), StandardCharsets.UTF_8);
		list = crawler.parseWebPage("packetstorm", html);
		fine = fine && list.size() > 0;

		html = FileUtils.readFileToString(new File("src/test/resources/test-packetstorm-advisory.html"), StandardCharsets.UTF_8);
		list = crawler.parseWebPage("packetstorm", html);
		fine = fine && list.size() > 0;

		html = FileUtils.readFileToString(new File("src/test/resources/test-packetstorm-cvedetail.html"), StandardCharsets.UTF_8);
		list = crawler.parseWebPage("packetstorm.html", html);
		fine = fine && list.size() > 0;

		assertTrue(fine);
	}

	@Test
	public void testPacketStormDailyFeed() {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		try {
			String link = "https://packetstormsecurity.com/files/date/2021-05-04/";
			String html = IOUtils.toString(new URL(link), StandardCharsets.UTF_8);
			List<CompositeVulnerability> list = new CveCrawler(propertiesNvip).parseWebPage(link, html);
			assertTrue(list.size() > 0);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
