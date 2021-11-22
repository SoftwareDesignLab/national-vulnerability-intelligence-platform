/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;

import edu.rit.se.nvip.cvereconcile.CveReconciler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Vulnerability;

/**
 * 
 * @author axoeec
 *
 */
public interface CveParserInterface {
	String regexCVEID = "CVE-[0-9]+-[0-9]+";
	String regexVersionInfo = "(?:(\\d+\\.(?:\\d+\\.)*\\d+))";
	String regexRepeatingCVEID = "(CVE-[0-9]+-[0-9]+).{1,}\\1";
	String regexAllCVERelatedContent = ".*(affect|attack|bypass|cve|execut|fix|flaw|permission|vulnerab|CVE|Mitigat|(?:(\\d+\\.(?:\\d+\\.)*\\d+))).*";
	String regexDateFormat = "([a-zA-Z]+ [0-9]+, [0-9]+)";
	String regexDateFormatNumeric = "[0-9]+[-/][0-9]+[-/][0-9]+";

	String regexChinese = "\\p{IsHan}";

	// abstract parser
	List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML);

}
