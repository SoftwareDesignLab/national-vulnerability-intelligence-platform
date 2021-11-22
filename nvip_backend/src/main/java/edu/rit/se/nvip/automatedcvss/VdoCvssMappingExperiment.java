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
package edu.rit.se.nvip.automatedcvss;

import java.io.File;
import java.io.FileReader;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.opencsv.CSVParser;
import com.opencsv.CSVParserBuilder;
import com.opencsv.CSVReader;
import com.opencsv.CSVReaderBuilder;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * @author axoeec
 *
 */
public class VdoCvssMappingExperiment {

	private static Logger logger = LogManager.getLogger(VdoCvssMappingExperiment.class);
	static NumberFormat formatter = new DecimalFormat("#0.00");

	public static void main(String[] args) {
		VdoCvssMappingExperiment vdoBasedCvssExperiment = new VdoCvssMappingExperiment();

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();

		// partialCvssVectorGenerator.testAutomatedCvssScoring(propertiesNvip.getDataDir(),
		// trainingDataInfo[0], trainingDataInfo[1], "NB");
		String approach = "ML";
		String method = "Vote";
		String pickleFileYear = "2015-2019"; // the pickle file that the Python script uses
		vdoBasedCvssExperiment.testAutomatedCvssScoring(propertiesNvip.getDataDir(), trainingDataInfo[0], trainingDataInfo[1], approach, method, pickleFileYear);

	}

	/**
	 * This method was written to test automated CVSS scoring based on the predicted
	 * VDO labels. Currently it tests the approach on 2021 CVEs.
	 * 
	 * @param rootPath
	 * @param trainingDataPath
	 * @param trainingDataFiles
	 * @param approach
	 * @param method
	 */
	private void testAutomatedCvssScoring(String rootPath, String trainingDataPath, String trainingDataFiles, String approach, String method, String pickleFileYear) {
		CvssScoreCalculator cvssScoreCalculator = new CvssScoreCalculator();
		CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataPath, trainingDataFiles, approach, method, true);
		PartialCvssVectorGenerator partialCvssVectorGenerator = new PartialCvssVectorGenerator();

		// cveCharacterizer.getCveClassifier().resetClassifier(new NaiveBayes());
		// Map<String, ArrayList<String[]>> prediction =
		// cveCharacterizer.characterizeCveForVDO(cveDesc,
		// true);

		try {
			String dataPath = rootPath + "/nvd-cve.csv";
			String time = System.currentTimeMillis() / 1000 / 60 + "";
			String outputPath = rootPath + "/cvss-experiment/nvd-cve-2020-2021-cvss-" + method + "-" + pickleFileYear + "-time-" + time + ".csv";
			CSVParser csvParser = new CSVParserBuilder().withSeparator('|').build();
			CSVReader reader = new CSVReaderBuilder(new FileReader(dataPath)).withCSVParser(csvParser).build();

			String[] nextLine;
			StringBuffer stringBuffer = new StringBuffer("CveId, Mean, Min, Max, StdDev, NvdCvss, AV, AC, PR, UI, S, C, I, A\n");
			int cveCount = 0;
			int correctCount = 0;
			int ignoredCveCount = 0;
			int notAssignedByNvdCount = 0;
			double sumAbsResidual = 0;
			double sumMean = 0;
			while ((nextLine = reader.readNext()) != null) {

				String cveId = nextLine[0];

				String[] cveParts = cveId.split("-");
				if (cveParts.length < 3)
					continue; // either header, i.e. CVE-ID or error in data

				/**
				 * Use 2020 CVEs, after 14000, because training data included data before
				 * CVE-2020-14000. Include 2021 CVEs as well
				 */
				int cveYear = 0, cveNumber = 0;
				try {
					cveYear = Integer.parseInt(cveParts[1]);
					cveNumber = Integer.parseInt(cveParts[2]);
				} catch (Exception e) {
					e.printStackTrace(); // might be header string?
				}
				if ((cveYear == 2020 && cveNumber > 14000) || cveYear == 2021) {

					String cveDesc = nextLine[1];
					if (nextLine[2].contains("?")) {
						notAssignedByNvdCount++;
						continue; // ignore CVEs that have ? as CVSS score in NVD data
					}

					double nvdCvss = Double.parseDouble(nextLine[2]);
					// characterize CVE
					Map<String, ArrayList<String[]>> predictionsForVuln = cveCharacterizer.characterizeCveForVDO(cveDesc, true);

					// generate partial CVSS vector from VDO prediction
					String[] cvssVec = partialCvssVectorGenerator.getCVssVector(predictionsForVuln);

					// get CVSS mean/min/max etc from Python sscript
					double[] cvssMetrics = cvssScoreCalculator.getCvssScoreJython(cvssVec);
					String strCvss = Arrays.deepToString(cvssVec).replace("[", "").replace("]", "");

					double meanCvss = cvssMetrics[0];
					double minCvss = cvssMetrics[1];
					double maxCvss = cvssMetrics[2];
					double stdDevCvss = cvssMetrics[3];

					if (meanCvss == -1 || meanCvss == 0) {
						logger.info("Ignoring " + meanCvss + " to meanCvss ( Python method returned -1)!");
						logger.info("+++Cve Id: " + cveId + "\tMean Cvss: " + meanCvss + "\tCvss Vector: " + Arrays.deepToString(cvssVec) + "\tScores: " + Arrays.toString(cvssMetrics) + "\tDescription:" + cveDesc);
						meanCvss = sumMean / (cveCount * 1.0);// if no partial CVSS match
						ignoredCveCount++;
						continue;// skip for now
					}
					sumAbsResidual += Math.abs(meanCvss - nvdCvss);
					sumMean = +meanCvss;
					cveCount++;

					// if the meanCvss score is between nvdCvss-stdDevCvss and nvdCvss+stdDevCvss,
					// assume correct!
					if (nvdCvss >= (meanCvss - stdDevCvss) && nvdCvss <= (meanCvss + stdDevCvss))
						correctCount++;

					logger.info(cveId + "\tMean Cvss: " + meanCvss + "\tNvd Cvss: " + nvdCvss + "\tCvss vector: " + strCvss);
					stringBuffer.append(cveId + "," + formatter.format(meanCvss) + "," + formatter.format(minCvss) + "," + formatter.format(maxCvss) + "," + formatter.format(stdDevCvss) + "," + nvdCvss + "," + strCvss + "\n");
				}
			} // while ((nextLine = reader.readNext()) != null) {

			double meanAbsErr = sumAbsResidual * 1.0 / cveCount;

			stringBuffer.append("Mean Absolute Error," + formatter.format(meanAbsErr) + "\n");
			stringBuffer.append("Total CVEs," + cveCount + "\n");
			stringBuffer.append("CVEs (-1 mean)," + ignoredCveCount + "\n");
			stringBuffer.append("CVEs (no CVSS in NVD)," + notAssignedByNvdCount + "\n");
			// stringBuffer.append("# of CVEs that are within mean+/-std dev," +
			// correctCount + "\n");

			FileUtils.writeStringToFile(new File(outputPath), stringBuffer.toString());

		} catch (Exception e) {
			e.printStackTrace();

		}

	}

}
