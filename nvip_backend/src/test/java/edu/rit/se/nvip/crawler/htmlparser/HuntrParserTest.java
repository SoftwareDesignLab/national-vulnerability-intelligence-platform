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

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static junit.framework.TestCase.*;
import static junit.framework.TestCase.assertEquals;

public class HuntrParserTest extends AbstractParserTest {

    @Test
    public void testHuntrCVE() {
        String html = safeReadHtml("src/test/resources/test-huntr.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://huntr.dev/bounties/2d4d309e-4c96-415f-9070-36d0815f1beb/",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-1127", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("division by zero in fuction"));
        assertFalse(vuln.getDescription().contains("was it not verification as a vulnerability?"));
        assertEquals("2023-02-19", vuln.getPublishDate());
        // ensure proper '6 days ago' parse
        LocalDate today = LocalDate.now();
        LocalDate lastModified = LocalDate.parse(vuln.getLastModifiedDate());
        long between = ChronoUnit.DAYS.between(lastModified, today);
        assertEquals(6, between);
    }

    @Test
    public void testHuntrNoCVE() {
        String html = safeReadHtml("src/test/resources/test-huntr-no.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://huntr.dev/bounties/4cb54865-bcd5-4bf4-8c09-2b1f00fea842/",
                html
        );
        assertEquals(0, list.size());
    }
}
