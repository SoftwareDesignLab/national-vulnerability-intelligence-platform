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

	String TEST_DESCRIPTION_CVE = "Usage of temporary files with insecure permissions by the Apache James server allows an attacker with local access to access private user data in transit. Vulnerable components includes the SMTP stack and IMAP APPEND command. This issue affects Apache James server version 3.7.2 and prior versions.";
	String TEST_DESCRIPTION_SECURITY = "A flaw was found in PHP. This issue occurs due to an uncaught integer overflow in PDO::quote() of PDO_SQLite returning an improperly quoted string. With the implementation of sqlite3_snprintf(), it is possible to force the function to return a single apostrophe if the function is called on user-supplied input without any length restrictions in place.";

	@Test
	public void testRedHat() throws IOException {

		RedHatParser parser = new RedHatParser("redhat");
		String html = FileUtils.readFileToString(new File("src/test/resources/test-redhat-cve.html"));
		List<CompositeVulnerability> list = parser.parseWebPage("redhat", html);

		CompositeVulnerability sample = list.get(0);

		assertEquals(1, list.size());
		assertEquals("CVE-2022-45935", sample.getCveId());
		assertEquals(TEST_DESCRIPTION_CVE, sample.getDescription());
	}

    @Test
	public void testSecurityRedHat() throws IOException {

		SecurityRedHatParser parser = new SecurityRedHatParser("redhat");
		String html = FileUtils.readFileToString(new File("src/test/resources/test-redhat-security.html"));
		List<CompositeVulnerability> list = parser.parseWebPage("redhat", html);
		
		CompositeVulnerability sample = list.get(0);

		assertEquals(10, list.size());
		assertEquals("CVE-2022-31631", sample.getCveId());
		assertEquals(TEST_DESCRIPTION_SECURITY, sample.getDescription());


	}

}
