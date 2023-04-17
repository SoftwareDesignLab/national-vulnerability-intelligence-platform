
/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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
import static org.junit.Assert.assertEquals;

/**
 * Test Parser for VMWare Security Advisories Page
 * @author aep7128
 *
 * There is an older version of this page for earlier CVEs,
 * but CVE Descriptions aren't accuratly shown (ex. 4 CVEs have the same description,
 * then redirects to MITRE), we may want to ignore those cases for now. Just test on the recent web page layout
 *
 */
public class VMWareAdvisoriesTest extends AbstractParserTest {

	/**
	 * Test Parser for page that has 1 CVE
	 * @throws IOException
	 */
	@Test
	public void testVMWareAdvisoriesSingleCVE() throws IOException {

		CveCrawler crawler = getCrawler();
		String html = FileUtils.readFileToString(new File("src/test/resources/test-vmware-advisories-single-cve.html"), StandardCharsets.UTF_8);
		List<CompositeVulnerability> list = crawler.parseWebPage("https://www.vmware.com/security/advisories/VMSA-2023-0003.html", html);

		assertEquals(list.size(), 1);

		CompositeVulnerability vuln = list.get(0);

		assertEquals(vuln.getCveId(), "CVE-2023-20854");
		assertEquals(vuln.getDescription(), "VMware Workstation contains an arbitrary file deletion vulnerability. VMware has evaluated the severity of this issue to be in the Important severity range with a maximum CVSSv3 base score of 7.8.");
		assertEquals(vuln.getPublishDate(), "2023-02-02");
		assertEquals(vuln.getLastModifiedDate(), "2023-02-02");

	}

	/**
	 * Test Parser for page with multiple CVEs
	 * @throws IOException
	 */
	@Test
	public void testVMWareAdvisoriesMultiCVE() throws IOException {

		CveCrawler crawler = getCrawler();
		String html = FileUtils.readFileToString(new File("src/test/resources/test-vmware-advisories-multi-cve.html"), StandardCharsets.UTF_8);
		List<CompositeVulnerability> list = crawler.parseWebPage("https://www.vmware.com/security/advisories/VMSA-2023-0001.html", html);

		assertEquals(list.size(), 4);

		CompositeVulnerability vuln = list.get(0);

		assertEquals("CVE-2022-31706", vuln.getCveId());
		assertEquals("The vRealize Log Insight contains a Directory Traversal Vulnerability. VMware has evaluated the severity of this issue to be in the critical severity range with a maximum CVSSv3 base score of 9.8.", vuln.getDescription());
		assertEquals("2023-01-24", vuln.getPublishDate());
		assertEquals("2023-01-31", vuln.getLastModifiedDate());

	}

}
