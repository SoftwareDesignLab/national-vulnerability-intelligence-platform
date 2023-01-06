package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class RedHatParserTest {

	@Test
	public void testSearchRedHat() throws IOException {

		SearchRedHatParser parser = new SearchRedHatParser("redhat");
		String html = FileUtils.readFileToString(new File("src/test/resources/test-redhat-search.html"));
		List<CompositeVulnerability> list = parser.parseWebPage("redhat", html);

		assertEquals(4, list.size());

	}

    @Test
	public void testSecurityRedHat() throws IOException {

		SecurityRedHatParser parser = new SecurityRedHatParser("redhat");
		String html = FileUtils.readFileToString(new File("src/test/resources/test-redhat-security.html"));
		List<CompositeVulnerability> list = parser.parseWebPage("redhat", html);
		assertEquals(10, list.size());

	}

}
