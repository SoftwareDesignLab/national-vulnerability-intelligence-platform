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

/**
 * 
 * @author axoeec
 *
 */
public class CveParserFactory {

	/**
	 * return the parser for this Url
	 */
	public AbstractCveParser createParser(String sPageUrl) {
		if (sPageUrl == null) {
			return new NullParser();
		}

		if (sPageUrl.contains("tenable.com") && !sPageUrl.contains("blog")) {
			if (sPageUrl.contains("security"))
				return new TenableSecurityParser("tenable");
			else
				return new TenableCveParser("tenable");
		}
		else if (sPageUrl.contains("exploit-db") && sPageUrl.contains("exploits"))
			return new ExploitDBParser("exploit-db");
		else if (sPageUrl.contains("kb.cert"))
			return new KbCertCveParser("kb.cert");
		else if (sPageUrl.contains("packetstorm"))
			return new PacketStormParser("packetstorm");
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
		}
		else if (sPageUrl.contains("vmware") && sPageUrl.contains("advisories"))
			return new VMWareAdvisoriesParser("vmware");
		else if (sPageUrl.contains("bugzilla"))
			return new BugzillaParser("bugzilla");
		else if (sPageUrl.contains("anquanke"))
			return new AnquankeParser("anquanke");
		else if (sPageUrl.contains("seclists"))
			return new SeclistsParser("seclists");
		else if (sPageUrl.contains("redhat") && sPageUrl.contains("security")) {
			if (sPageUrl.contains("security-updates"))
				return new SecurityRedHatParser("redhat");
			else if (sPageUrl.contains("cve"))
				return new RedHatParser("redhat");
		}
		else if (sPageUrl.contains("bosch") && sPageUrl.contains("security-advisories"))
			return new BoschSecurityParser("bosch");
		else if (sPageUrl.contains("cloud.google") && sPageUrl.contains("bulletins"))
			return new GoogleCloudParser("google");
		else if (sPageUrl.contains("atlassian"))
			return new AtlassianParser("atlassian");
		else if (sPageUrl.contains("mend.io"))
			return new MendParser("mend.io");
		else if (sPageUrl.contains("autodesk"))
			return new AutodeskParser("autodesk");
		else if (sPageUrl.contains("jenkins.io"))
			return new JenkinsParser("jenkins.io");
		else if (sPageUrl.contains("coresecurity"))
			return new CoreParser("coresecurity");
		else if (sPageUrl.contains("mozilla"))
			return new MozillaParser("mozilla");
		else if (sPageUrl.contains("intel"))
			return new IntelParser("intel");
		else if (sPageUrl.contains("msrc"))
			return new MicrosoftParser("msrc");
		else if (sPageUrl.contains("trustwave"))
			return new TrustWaveParser("trustwave");
		else if (sPageUrl.contains("zerodayinitiative"))
			return new TrendMicroParser("zerodayinitiative");
		else if (sPageUrl.contains("tibco"))
			return new TibcoParser("tibco");
		else if (sPageUrl.contains("android"))
			return new AndroidParser("android");
		else if (sPageUrl.contains("huntr"))
			return new HuntrParser("huntr");
		else if (sPageUrl.contains("jvn"))
			return new JVNParser("jvn");
		else if (sPageUrl.contains("github.com/advisories"))
			return new GitHubAdvisoryParser("github.com/advisories");
		else if (sPageUrl.contains("curl"))
			return new CurlParser("curl");
		else if (sPageUrl.contains("snyk.io"))
			return new SnykParser("snyk.io");
		else if (sPageUrl.contains("acronis"))
			return new AcronisParser("acronis");
		else if (sPageUrl.contains("veritas"))
			return new VeritasParser("veritas");
		else if (sPageUrl.contains("adobe"))
			return new AdobeParser("adobe");
		else if (sPageUrl.contains("aliasrobotics"))
			return new AliasRoboParser("aliasrobotics");
		else if (sPageUrl.contains("amperecomputing.com/products/product-security"))
			return new AmpereRootParser("amperecomputing.com/products/product-security");
		else if (sPageUrl.contains("arubanetworks"))
			return new ArubaParser("arubanetworks");
		else if (sPageUrl.contains("cybersecurityworks"))
			return new ZeroDaysParser("cybersecurityworks");
		else if (sPageUrl.contains("dragos"))
			return new DragosParser("dragos");
		else if (sPageUrl.contains("cyberark"))
			return new CyberArkRootParser("cyberark");


		// sources that you want to ignore
		// we ignore mitre/nvd because we pull their up to date CVEs from Github
		else if (sPageUrl.contains("mitre.org") || sPageUrl.contains("nist.gov"))
			return new NullParser();

		return new GenericCveParser("nat_available");
	}

}
