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

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SecurityGentooParserTest extends AbstractParserTest {


	@Test
	public void testSecurityGentooSingle() {
		String html = safeReadHtml("src/test/resources/test-security-gentoo-single.html");
		List<CompositeVulnerability> list = new SecurityGentooParser("gentoo").parseWebPage("security.gentoo", html);
		assertEquals(1, list.size());
		CompositeVulnerability vuln = list.get(0);
		assertEquals("CVE-2005-0453", vuln.getCveId());
		assertEquals("2005/02/15 00:00:00", vuln.getPublishDate());
		assertEquals("lighttpd uses file extensions to determine which elements are programs that should be executed and which are static pages that should be sent as-is. By appending %00 to the filename, you can evade the extension detection mechanism while still accessing the file. A remote attacker could send specific queries and access the source of scripts that should have been executed as CGI or FastCGI applications.",
				vuln.getDescription());
	}

	@Test
	public void testSecurityGentooMulti() {
		String html = safeReadHtml("src/test/resources/test-security-gentoo-multi.html");
		List<CompositeVulnerability> list = new SecurityGentooParser("gentoo").parseWebPage("security.gentoo", html);
		assertEquals(3, list.size());
		CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-3171");
		assertNotNull(vuln);
		assertEquals("2023/01/11 00:00:00", vuln.getPublishDate());
		assertEquals("Inputs containing multiple instances of non-repeated embedded messages with repeated or unknown fields causes objects to be converted back and forth between mutable and immutable forms, resulting in potentially long garbage collection pauses. Crafted input can trigger a denial of service via long garbage collection pauses.",
				vuln.getDescription());
	}
}
