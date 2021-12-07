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
}
