package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class SecurityGentooParserTest {

	@Test
	public void testSecurityGentoo() throws IOException {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		String html = FileUtils.readFileToString(new File("src/test/resources/test-gentoo-cvedetail.html"));
		CveCrawler crawler = new CveCrawler(propertiesNvip);
		List<CompositeVulnerability> list = crawler.parseWebPage("gentoo", html);
		boolean fine = list.size() == 1;

		assertEquals(true, fine);
	}
}
