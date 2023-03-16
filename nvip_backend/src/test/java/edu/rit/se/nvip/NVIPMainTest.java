package edu.rit.se.nvip;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

public class NVIPMainTest {

	@Test
	public void testEssentialData() {

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		/**
		 * Test the existence of VDO training data for characterization
		 */

		String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
		int kbyte = 1024;
		int mbyte = kbyte * 1024;

		String vdoTrainingFile = trainingDataInfo[0] + trainingDataInfo[1].split(",")[0];
		File f3 = new File(vdoTrainingFile);

		int f3Length = (int) f3.length() / kbyte;

		assertEquals(true, f3.exists() && (f3Length > 10));
	}

	/**
	 * Test CVE Crawl Function

	@Test
	public void testCrawlCVE() {
		NVIPMain main = new NVIPMain(false);

		List<String> urls = main.startNvip();
		HashMap<String, CompositeVulnerability> vulns = main.crawlCVEs(urls);

		System.out.println(vulns);
	}*/

	/**
	 * Test description comparing via Git and CNA descriptions
	 */
	@Test
	public void testDescriptionCompare() {
		String testDescriptionCNA = "Test CVE Description, this should not be changed";
		String testDescriptionReserved = "** RESERVED ** This candidate has been reserved";
		String expectedResult = "** RESERVED ** - NVIP Description: Test CVE Description, this should not be changed";

		HashMap<String, CompositeVulnerability > cvehashMapGithub = new HashMap<>();
		cvehashMapGithub.put("CVE-2022-30080", new CompositeVulnerability(0, "sourcURL",
				"CVE-2022-30080", null, "2022-05-02", "2022-05-02",
				testDescriptionReserved, "domain"));

		HashMap<String, CompositeVulnerability > cveHashMapScrapedFromCNAs = new HashMap<>();
		cveHashMapScrapedFromCNAs.put("CVE-2022-30080", new CompositeVulnerability(0, "sourcURL",
				"CVE-2022-30080", null, "2022-05-02", "2022-05-02",
				testDescriptionCNA, "domain"));

		//HashMap<String, CompositeVulnerability> merge = new NVIPMain(false).
		//		mergeCVEsDerivedFromCNAsAndGit(cvehashMapGithub, cveHashMapScrapedFromCNAs);

		//assertEquals(expectedResult, merge.get("CVE-2022-30080").getDescription());

	}

	/**
	 * Test CVE Process Function
	 */
	@Test
	public void testCVEProcess() {;

		String testDescription = "Test CVE Description, this should not be changed";

		HashMap<String, CompositeVulnerability> v = new HashMap<>();
		v.put("CVE-2022-30080", new CompositeVulnerability(0, "sourcURL", "CVE-2022-30080", null,
				"2022-05-02", "2022-05-02",
				testDescription, "domain"));

		v.put("CVE-2000-00000", new CompositeVulnerability(0, "sourcURL", "CVE-2000-00000", null,
				"2022-05-02", "2022-05-02",
				testDescription, "domain"));

		NVIPMain main = new NVIPMain(false);
		/*HashMap<String, List<Object>> maps = main.processCVEs(v);

		System.out.println(maps);

		CompositeVulnerability vuln1 = (CompositeVulnerability) maps.get("all").get(0);
		CompositeVulnerability vuln2 = (CompositeVulnerability) maps.get("all").get(1);

		assertEquals(2, maps.get("all").size());
		assertEquals(2, maps.get("nvd").size());
		assertEquals(1, maps.get("mitre").size());
		assertEquals(testDescription, vuln1.getDescription());
		assertEquals(testDescription, vuln2.getDescription());*/
	}
}
