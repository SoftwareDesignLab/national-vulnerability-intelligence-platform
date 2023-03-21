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

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class MozillaParserTest extends AbstractParserTest {

    @Test
    public void testMozzilaSingle() {
        String html = safeReadHtml("src/test/resources/test-mozilla-single.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.mozilla.org/en-US/security/advisories/mfsa2021-06/",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2020-16048", vuln.getCveId());
        assertEquals("February 5, 2021", vuln.getPublishDate());
        assertEquals("February 5, 2021", vuln.getLastModifiedDate());
        assertTrue(vuln.getDescription().contains("simply multiplied the row pitch with the pixel height"));
    }

    @Test
    public void testMozillaMultiple() {
        String html = safeReadHtml("src/test/resources/test-mozilla-multiple.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.mozilla.org/en-US/security/advisories/mfsa2023-07/",
                html
        );
        assertEquals(13, list.size());
        CompositeVulnerability vuln = list.get(2);
        assertEquals("CVE-2023-25730", vuln.getCveId());
        assertEquals("February 15, 2023", vuln.getPublishDate());
        assertEquals("February 15, 2023", vuln.getLastModifiedDate());
        assertTrue(vuln.getDescription().contains("resulting in potential user confusion or spoofing attacks"));
        assertFalse(vuln.getDescription().contains("iframe's unredacted URI when interaction"));
    }
}
