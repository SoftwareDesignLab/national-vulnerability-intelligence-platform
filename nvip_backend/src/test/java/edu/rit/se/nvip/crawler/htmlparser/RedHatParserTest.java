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

	String TEST_DESCRIPTION_SEARCH = "A flaw was found in PHP. This issue occurs due to an uncaught integer overflow in PDO::quote() of PDO_SQLite returning an improperly quoted string. With the implementation of sqlite3_snprintf(), it is possible to force the function to return a single apostrophe if the function is called on user-supplied input without any length restrictions in place.";
	String TEST_DESCRIPTION_SECURITY = "A flaw was found in PHP. This issue occurs due to an uncaught integer overflow in PDO::quote() of PDO_SQLite returning an improperly quoted string. With the implementation of sqlite3_snprintf(), it is possible to force the function to return a single apostrophe if the function is called on user-supplied input without any length restrictions in place.";

	@Test
	public void testSearchRedHat() throws IOException {

		SearchRedHatParser parser = new SearchRedHatParser("redhat");
		String html = FileUtils.readFileToString(new File("src/test/resources/test-redhat-search.html"));
		List<CompositeVulnerability> list = parser.parseWebPage("redhat", html);

		//for (CompositeVulnerability vuln: list) {
		//	System.out.println(vuln.toString());
		//	System.out.println("");
		//}

		assertEquals(4, list.size());
		//assertEquals(TEST_DESCRIPTION_SEARCH, list.get(0).getDescription());

	}

    @Test
	public void testSecurityRedHat() throws IOException {

		SecurityRedHatParser parser = new SecurityRedHatParser("redhat");
		String html = FileUtils.readFileToString(new File("src/test/resources/test-redhat-security.html"));
		List<CompositeVulnerability> list = parser.parseWebPage("redhat", html);
		
		assertEquals(10, list.size());
		assertEquals(TEST_DESCRIPTION_SECURITY, list.get(0).getDescription());


	}

}
