package edu.rit.se.nvip.characterizer;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class CveCharacterizerTest {
	@Test
	public void testCveCharacterization() {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();

		// test prediction
		String cveDesc = "7.2 HIGH9.0 HIGHCVE-2020-11544 Ã¢â‚¬â€� An issue was discovered in Project Worlds Official Car Rental System 1. It allows the admin user to run commands on the server with their account because the upload section on the file-manager page contains an arbitrary file upload vulnerability via... read CVE-2020-11544 Published: April 06, 2020; 12:15:13 PM -04:00 CVE-2020-11544read CVE-2020-11544V3.1:7.2 HIGH6.5 MEDIUM";

		CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], "ML", "NB", true);
		// cveCharacterizer.getCveClassifier().resetClassifier(new NaiveBayes());
		Map<String,ArrayList<String[]>> prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, true);

		assertTrue(prediction.size() > 0);
	}
}
