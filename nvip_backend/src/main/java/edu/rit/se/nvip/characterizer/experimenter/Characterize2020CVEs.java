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
package edu.rit.se.nvip.characterizer.experimenter;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.opencsv.CSVParser;
import com.opencsv.CSVParserBuilder;
import com.opencsv.CSVReader;
import com.opencsv.CSVReaderBuilder;

import edu.rit.se.nvip.automatedcvss.PartialCvssVectorGenerator;
import edu.rit.se.nvip.automatedcvss.enums.VdoNounGroup;
import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * This class was written to characterize CVEs at a given year with a given ML
 * method. The goal is to map CVEs to CWEs based on VDO labels.
 * 
 * @author axoeec
 *
 */
public class Characterize2020CVEs {

	private static Logger logger = LogManager.getLogger(PartialCvssVectorGenerator.class);
	static NumberFormat formatter = new DecimalFormat("#0.00");

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Characterize2020CVEs testModel = new Characterize2020CVEs();

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
		String rootPath = propertiesNvip.getDataDir();

		String yearToCharacterize = "2020"; // must be 4 digits!
		String mLearningAlg = "Vote"; // must be a valid ML algorithm implemented in the system like NB, SVM, RF, DT,
										// Vote etc.

		testModel.characterizeCVEsAtGivenYearUsingGivenMLAlgorithm(rootPath, trainingDataInfo, mLearningAlg, yearToCharacterize);

	}

	/**
	 * This method was written to characterize CVEs at a given year with a given ML
	 * method. Working with the NIST team to predict VDO labels for 2020 CVEs and
	 * use them to map CVEs to CWEs, considering impact method, logical impact and
	 * potential mitigation strategies.
	 * 
	 * 
	 * Make sure that you have the file named "nvd-cve.csv" under the data path.
	 * This file is supposed to give the up to date list of CVEs published by NVD.
	 * The first two columns of the file must be cve id and description. Column
	 * separator is assumed to be "|"
	 * 
	 * @param rootPath
	 * @param trainingDataInfo
	 * @param method
	 * @param year
	 */
	private void characterizeCVEsAtGivenYearUsingGivenMLAlgorithm(String rootPath, String[] trainingDataInfo, String method, String year) {

		CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], "ML", method, false);

		try {
			String dataPath = rootPath + "/nvd-cve.csv";
			String outputPath = rootPath + "/cvss-experiment/nvd-cve-2020-VDO-" + method + ".csv";
			CSVParser csvParser = new CSVParserBuilder().withSeparator('|').build();
			CSVReader reader = new CSVReaderBuilder(new FileReader(dataPath)).withCSVParser(csvParser).build();

			String[] nextLine;
			StringBuffer stringBuffer = new StringBuffer("CveId,group,label,confidence\n");
			while ((nextLine = reader.readNext()) != null) {
				String cveId = nextLine[0];

				// characterize only 2020 CVEs
				if (!cveId.contains("CVE-" + year + "-"))
					continue;

				String cveDesc = nextLine[1];

				// characterize CVE
				Map<String, ArrayList<String[]>> predictionsForVuln = cveCharacterizer.characterizeCveForVDO(cveDesc, true);

				for (String vdoNounGroup : predictionsForVuln.keySet()) {
					ArrayList<String[]> predictionsForNounGroup = predictionsForVuln.get(vdoNounGroup);
					String[] prediction = predictionsForNounGroup.get(0);
					stringBuffer.append(cveId + "," + vdoNounGroup + "," + prediction[0] + "," + prediction[1] + "\n");
					logger.info("Characterized CVE: " + cveId + " for " + vdoNounGroup + "\t: " + Arrays.deepToString(prediction));
				}

			}
			FileUtils.writeStringToFile(new File(outputPath), stringBuffer.toString());

		} catch (Exception e) {
			e.printStackTrace();

		}
	}

}
