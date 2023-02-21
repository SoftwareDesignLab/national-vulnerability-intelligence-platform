package edu.rit.se.nvip.characterizer;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.junit.Test;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
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

		//Test characterizeCveForVDO
		Map<String,ArrayList<String[]>> prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, true);
		assertTrue(prediction.size() > 0);

		prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, false);
		assertTrue(prediction.size() > 0);

		//Test characterizeCveList
		DatabaseHelper db = DatabaseHelper.getInstance();
		//String csvPath = "src/test/resources/test-composite-vuln-list.csv";
		String csvPath = propertiesNvip.getDataDir() + "/mitre-cve.csv";
		CsvUtils utils = new CsvUtils();
		List<String[]> data = utils.getDataFromCsv(csvPath);
		List<String[]> testData = new LinkedList<>();
		for (int i = 0; i < 10; i++) {
			testData.add(data.get(i));
		}
		// generate vuln list
		List<CompositeVulnerability> vulnList = new ArrayList<>();
		for (String[] line : testData) {
			String cveId = line[0];
			String description = line[1];
			if (description.contains("** RESERVED") || description.contains("** REJECT"))
				continue;
			CompositeVulnerability vuln = new CompositeVulnerability(0, null, cveId, null, null, null, description, null);
			vuln.setCveReconcileStatus(CompositeVulnerability.CveReconcileStatus.UPDATE);
			vulnList.add(vuln);
		}

		List<CompositeVulnerability> newList = cveCharacterizer.characterizeCveList(vulnList, db);
		assertEquals(10, newList.size());

		//Test getCvssScoreFromVdoLabels
	}
}
