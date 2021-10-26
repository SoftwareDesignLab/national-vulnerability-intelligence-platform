package edu.rit.se.nvip;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Vulnerability;
import edu.rit.se.nvip.model.VulnerabilityAttribsForUpdate;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * Update CVE descriptions with the ones pulled from Github. This process is run
 * periodically to flush automatically generated CVE descriptions with the ones
 * manually updated by security researchers.
 * 
 * @author axoeec
 *
 */
public class FlushCveDescriptionsFromMitreCsv {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	CsvUtils utils = new CsvUtils();

	public static void main(String[] args) {
		FlushCveDescriptionsFromMitreCsv updateCveDescriptionsOnNvip = new FlushCveDescriptionsFromMitreCsv();
		updateCveDescriptionsOnNvip.startUpdate();
	}

	private void startUpdate() {

		final String REJECTED = "** REJECT";
		final String RESERVED = "** RESERVED";

		// load properties file
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		UtilHelper.initLog4j(propertiesNvip);

		String csvPath = propertiesNvip.getDataDir() + "/mitre-cve.csv";
		DatabaseHelper db = DatabaseHelper.getInstance();

		List<String[]> data = utils.getDataFromCsv(csvPath);

		// generate vuln list
		List<CompositeVulnerability> vulnList = new ArrayList<>();
		for (String[] line : data) {
			String cveId = line[0];
			String description = line[1];
			if (description.contains(RESERVED) || description.contains(REJECTED))
				continue;
			CompositeVulnerability vuln = new CompositeVulnerability(0, null, cveId, null, null, null, description, null);
			vulnList.add(vuln);
		}

		// characterize
		String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
		CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], "ML", "Vote", false);
		cveCharacterizer.characterizeCveList(vulnList, db); // characterize

		// update db
		Map<String, Vulnerability> existingCves = db.getExistingVulnerabilities();
		int count = 0;
		int maxRunId = db.getMaxRunId();
		for (CompositeVulnerability vuln : vulnList) {
			try {
				// update database
				db.updateVulnerabilityDataFromCsv(vuln, existingCves, maxRunId);
			} catch (SQLException e) {
				logger.error("Error: {}", e.toString());
			}
			count++;
			if (count % 100 == 0)
				logger.info("Finished updating {} of {} CVes", count, vulnList.size());
		}

	}

}
