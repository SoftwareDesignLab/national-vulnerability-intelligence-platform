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

import static junit.framework.TestCase.*;
import static junit.framework.TestCase.assertEquals;

public class SnykParserTest extends AbstractParserTest {

    @Test
    public void testSnykCve() {
        String html = safeReadHtml("src/test/resources/test-snyk.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://security.snyk.io/vuln/SNYK-RUST-CRANELIFTCODEGEN-3357941",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-26489", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("translates code from an intermediate representation"));
        assertEquals("9 Mar 2023", vuln.getPublishDate());
    }

    @Test
    public void testSnykNoCve() {
        String html = safeReadHtml("src/test/resources/test-snyk-no.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://security.snyk.io/vuln/SNYK-PYTHON-BINGCHILLING2-3358386",
                html
        );
        assertEquals(0, list.size());
    }

    @Test
    public void testSnykCveDetailed() {
        String html = safeReadHtml("src/test/resources/test-snyk-details.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://security.snyk.io/vuln/SNYK-PHP-MOODLEMOODLE-3356645",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2021-36401", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("Escaping means that the application is coded to mark key char"));
        assertEquals("8 Mar 2023", vuln.getPublishDate());
    }
}
