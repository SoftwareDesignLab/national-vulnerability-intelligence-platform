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

/**
 * 
 * @author axoeec
 *
 */
public class CveParserFactory implements AbstractCveParserFactory<Object> {

	/**
	 * return the parser for this Url
	 */
	@Override
	public CveParserInterface createParser(String sPageUrl) {
		if (sPageUrl == null) {
			return new NullParser();
		}

		if (sPageUrl.contains("tenable") && !sPageUrl.contains("blog")) {
			if (sPageUrl.contains("security"))
				return new TenableSecurityParser("tenable");
			else
				return new TenableCveParser("tenable");
		} else if (sPageUrl.contains("oval.cisecurity"))
			return new OvalCiSecurityParser("oval.cisecurity");
		else if (sPageUrl.contains("exploit-db"))
			return new ExploitDBParser("exploit-db");
		else if (sPageUrl.contains("securityfocus") && !sPageUrl.contains("archive")) // archive pages have no consistent format
			return new SecurityfocusCveParser("securityfocus");
		else if (sPageUrl.contains("kb.cert"))
			return new KbCertCveParser("kb.cert");
		else if (sPageUrl.contains("packetstorm"))
			return new PacketStormParser("packetstorm");
		else if (sPageUrl.contains("securitytracker"))
			return new SecurityTrackerParser("securitytracker");
		else if (sPageUrl.contains("talosintelligence"))
			return new TalosIntelligenceParser("talosintelligence");

		// all gentoo pages in this if statement
		else if (sPageUrl.contains("gentoo")) {
			if (sPageUrl.contains("bugs"))
				return new BugsGentooParser("gentoo");
			else if (sPageUrl.contains("security"))
				return new SecurityGentooParser("gentoo");
			else if (sPageUrl.contains("news"))
				return new NullParser();
			else if (sPageUrl.contains("blogs"))
				return new NullParser();
			else
				return new GenericCveParser("nat_available");
		} else if (sPageUrl.contains("vmware") && sPageUrl.contains("advisories"))
			return new VMWareAdvisoriesParser("vmware");
		else if (sPageUrl.contains("vmware"))
			return new VMWareParser("vmware");
		else if (sPageUrl.contains("bugzilla"))
			return new BugzillaParser("bugzilla");
		else if (sPageUrl.contains("anquanke"))
			return new AnquankeParser("anquanke");
		else if (sPageUrl.contains("seclists"))
			return new SeclistsParser("seclists");
		else if (sPageUrl.contains("redhat")) {
			if (sPageUrl.contains("security"))
				return new SecurityRedHatParser("redhat");
			else 
				return new RedHatParser("redhat");
		}

		// sources that you want to ignore
		// we ignore mitre/nvd because we pull their up to date CVEs from Github
		else if (sPageUrl.contains("mitre.org") || sPageUrl.contains("nist.gov"))
			return new NullParser();

		return new GenericCveParser("nat_available");
	}

}
