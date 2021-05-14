package edu.rit.se.nvip;

import static org.junit.Assert.assertEquals;

import java.io.File;

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
		 * Test the existence essential data files: NVD/MITRE CVEs to compare against, VDO training data for
		 * characterization, Source URLS to crawl etc.
		 */

		String nvdPath = propertiesNvip.getNvdOutputCsvFullPath();
		String mitrePath = propertiesNvip.getMitreOutputCsvFullPath();
		String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
		String urlSources = propertiesNvip.getNvipUrlSourcesFullPath(); // crawled url sources stored here
		int kbyte = 1024;
		int mbyte = kbyte * 1024;
		File f1 = new File(nvdPath);
		File f2 = new File(mitrePath);
		
		String vdoTrainingFile = trainingDataInfo[0] + trainingDataInfo[1].split(",")[0];
		File f3 = new File(vdoTrainingFile);
		File f4 = new File(urlSources);

		int f1Length = (int) f1.length() / mbyte;
		int f2Length = (int) f2.length() / mbyte;
		int f3Length = (int) f1.length() / kbyte;

		assertEquals(true, f1.exists() && (f1Length > 30) && f2.exists() && (f2Length > 40) && f3.exists() && (f3Length > 80) && f4.exists());
	}
}
