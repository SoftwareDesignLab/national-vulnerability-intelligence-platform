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
package edu.rit.se.nvip.characterizer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.automatedcvss.CvssScoreCalculator;
import edu.rit.se.nvip.automatedcvss.PartialCvssVectorGenerator;
import edu.rit.se.nvip.characterizer.classifier.AbstractCveClassifier;
import edu.rit.se.nvip.characterizer.classifier.CveClassifierFactory;
import edu.rit.se.nvip.characterizer.classifier.EntropyBasedCveClassifier;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.exploitability.ImpactPredictor;
import edu.rit.se.nvip.exploitability.SeverityPredictor;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.CvssScore;
import edu.rit.se.nvip.model.VdoCharacteristic;
import edu.rit.se.nvip.model.Vulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;
import net.bytebuddy.asm.Advice.This;
import weka.classifiers.Classifier;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.functions.Logistic;
import weka.classifiers.functions.SMO;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;
import weka.core.converters.ArffSaver;
import weka.core.converters.CSVSaver;

/**
 * 
 * @author axoeec
 *
 */
public class CveCharacterizer {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private List<AbstractCveClassifier> myClassifierList = new ArrayList<AbstractCveClassifier>();
	private SeverityPredictor severityPredictor = null;
	private ImpactPredictor impactPredictor = null;

	/**
	 * these two vars are used to derive the CVSS vector from VDO labels and then
	 * use the vector to derive the CVSS score
	 */
	private PartialCvssVectorGenerator partialCvssVectorGenerator = new PartialCvssVectorGenerator();
	private CvssScoreCalculator cvssScoreCalculator = new CvssScoreCalculator();

	/**
	 * Construct a CVE Characterizer. You need to provide an initial training data
	 * as CSV. No incremental training this time.
	 * 
	 * @param trainingDataPath
	 * @param trainingDataFiles
	 * @param approach
	 * @param method
	 * @param loadSerializedModels
	 */
	public CveCharacterizer(String trainingDataPath, String trainingDataFiles, String approach, String method, boolean loadSerializedModels) {
		try {

			/**
			 * trainingDataPath may include multiple CSV files, if that is the case then
			 * train a model for each CSV file!
			 */

			String[] trainingDataFileArr = trainingDataFiles.split(",");
			for (String trainingDataFileName : trainingDataFileArr) {
				String vdoNounGroupName = trainingDataFileName.replace(".csv", "");
				trainingDataFileName = trainingDataPath + trainingDataFileName;
				// remove special chars?
				String sContent = FileUtils.readFileToString(new File(trainingDataFileName));
				sContent = sContent.replaceAll("[ '|\\\"|â€�|\\|]", " ");
				FileUtils.writeStringToFile(new File(trainingDataFileName), sContent, false);

				// pre-process training data and store it
				CvePreProcessor nvipPreProcessor = new CvePreProcessor(true);
				String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");
				String sCommaSeparatedAttribRows = nvipPreProcessor.preProcessFile(trainingDataFileName);

				FileUtils.writeStringToFile(new File(preProcessedTrainingDataFile), sCommaSeparatedAttribRows, false);
				logger.info("Raw training data at " + trainingDataFileName + " is processed and a CSV file is generated at " + preProcessedTrainingDataFile);

				// get CVE classification model
				CveClassifierFactory cveCharacterizerFactory = new CveClassifierFactory();
				AbstractCveClassifier aClassifier = cveCharacterizerFactory.getCveClassifier(approach, method, preProcessedTrainingDataFile);

				// assign a name to each classifier.
				aClassifier.setCveClassifierName(vdoNounGroupName);

				// store arff file
				// cveClassifier.convertCSVtoARFF(trainingDataOutputFilePath);

				// train the model
				aClassifier.trainMLModel();
				myClassifierList.add(aClassifier);
			}

		} catch (Exception e) {
			logger.error("An error occurred while tarining a classifier for CVE Characterizer! NVIP will not crash but CVE Characterizer will NOT work properly. Check your training data at "
					+ trainingDataPath + "\tException: " + e.toString());
		}

		try {
			if (loadSerializedModels) {
				MyProperties propertiesNvip = new MyProperties();
				propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
				severityPredictor = new SeverityPredictor(propertiesNvip.getDataDir());

				impactPredictor = new ImpactPredictor(propertiesNvip.getDataDir());
			}
		} catch (Exception e) {
			logger.error(e.toString());

		}
	}

	/**
	 * Characterize a given CVE description.
	 * 
	 * @param cveDesc
	 * @param bPredictMultiple TODO
	 * @return
	 * 
	 *         The VDO label and its associated probability
	 */
	public ArrayList<String[]> characterizeCve(String cveDesc, boolean bPredictMultiple) {
		CvePreProcessor cvePreProcessor = new CvePreProcessor(true);
		String cveDescProcessed = cvePreProcessor.preProcessLine(cveDesc);

		ArrayList<String[]> prediction = new ArrayList<String[]>();
		for (AbstractCveClassifier aClassifier : myClassifierList) {
			ArrayList<String[]> predictionFromClassifier = aClassifier.predict(cveDescProcessed, bPredictMultiple);
			prediction.addAll(predictionFromClassifier);
		}

		return prediction;
	}

	/**
	 * Method overload!
	 * 
	 * @param cveDesc
	 * @param bPredictMultiple
	 * @return
	 */
	public Map<String, ArrayList<String[]>> characterizeCveForVDO(String cveDesc, boolean bPredictMultiple) {
		CvePreProcessor cvePreProcessor = new CvePreProcessor(true);
		String cveDescProcessed = cvePreProcessor.preProcessLine(cveDesc);

		Map<String, ArrayList<String[]>> prediction = new HashMap<String, ArrayList<String[]>>();
		for (AbstractCveClassifier aClassifier : myClassifierList) {
			ArrayList<String[]> predictionFromClassifier = aClassifier.predict(cveDescProcessed, bPredictMultiple);
			String vdoNounGroup = aClassifier.getCveClassifierName();
			prediction.put(vdoNounGroup, predictionFromClassifier);
		}

		return prediction;
	}

	/**
	 * characterize vulnerabilities in the given <cveList>
	 * 
	 * @param cveList
	 */
	public List<CompositeVulnerability> characterizeCveList(List<CompositeVulnerability> cveList, DatabaseHelper databaseHelper) {

		long start = System.currentTimeMillis();
		int totCharacterized = 0;

		Map<String, Integer> cvssSeverityLabels = databaseHelper.getCvssSeverityLabels();
		Map<String, Integer> vdoLabels = databaseHelper.getVdoLabels();
		Map<String, Integer> vdoNounGroups = databaseHelper.getVdoNounGrpups();

		int countNotChanged = 0;
		int countBadDescription = 0;

		// predict for each CVE, the model was trained in the constructor!
		for (int i = 0; i < cveList.size(); i++) {
			CompositeVulnerability vulnerability = null;
			try {
				vulnerability = cveList.get(i);

				String cveDesc = vulnerability.getDescription();
				if (cveDesc == null || cveDesc.length() < 50) {
					countBadDescription++;
					continue; // if no description or old CVE skip!
				}
				if (vulnerability.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE) {
					countNotChanged++;
					continue; // the same CVE in db
				}

				totCharacterized++;

				/**
				 * To skip the rest of the characterization for the very first run or if the
				 * system has not been run for a long time. The process could be time consuming
				 * for too many CVEs
				 */
				if (totCharacterized > 5000) 
					break;
				
				// characterize CVE
				Map<String, ArrayList<String[]>> prediction = characterizeCveForVDO(cveDesc, true);
				for (String vdoNounGroup : prediction.keySet()) {
					ArrayList<String[]> predictionsForNounGroup = prediction.get(vdoNounGroup);
					Integer vdoNounGroupId = vdoNounGroups.get(vdoNounGroup);
					if (vdoNounGroupId == null) {
						logger.warn("No entry was found for vdo noun group: {}! Please add it to the db.", vdoNounGroup);
						continue;
					}
					for (String[] item : predictionsForNounGroup) {
						Integer vdoLabelId = vdoLabels.get(item[0]);
						if (vdoLabelId == null)
							logger.warn("No entry was found for vdo noun group label: {}! Please add it to the db", vdoLabelId);
						else
							vulnerability.addVdoCharacteristic(new VdoCharacteristic(vulnerability.getCveId(), vdoLabelId.intValue(), Double.parseDouble(item[1]), vdoNounGroupId.intValue()));
					}
				}

				// get severity
				double[] cvssScore = getCvssScoreFromVdoLabels(prediction); // get mean/minimum/maximum/std dev
				Integer severityId = cvssSeverityLabels.get(getSeverityLabelFromCvssScore(cvssScore[0])); // use mean
				if (severityId == null)
					logger.warn("No entry was found for severity class {}! Please add it to the db.", severityId);
				else {
					CvssScore score = new CvssScore(vulnerability.getCveId(), severityId.intValue(), 0.5, String.valueOf(cvssScore[0]), 0.5);
					vulnerability.addCvssScore(score);
				}

				// update list
				cveList.set(i, vulnerability);

				// log
				if (totCharacterized % 100 == 0 && totCharacterized > 0) {
					double percent = (totCharacterized + countBadDescription + countNotChanged) * 1.0 / cveList.size() * 100;
					logger.info("Characterized {} of {} total CVEs. Skipping {} CVEs - [{} bad/null and {} not changed descriptions], {}% done! ", totCharacterized, cveList.size(),
							(countBadDescription + countNotChanged), countBadDescription, countNotChanged, Math.round(percent));
				}
			} catch (Exception e) {
				logger.error("Error during chaarcterization: {}, CVE: {}", e, vulnerability);
			}
		} // for
		long seconds = (System.currentTimeMillis() - start) / 1000;
		double avgTime = seconds * 1.0 / totCharacterized;
		logger.info("***Characterized {} of total {} CVEs in {} seconds! Avg time(s): {}", totCharacterized, cveList.size(), seconds, avgTime);
		logger.info("{} CVEs did not have a good description, and {} CVEs had the same description (after reconciliation) and skipped!", countBadDescription, countNotChanged);

		return cveList;
	}

	/**
	 * Underlying abstract CVE Classifier. <cveClassifier> is using either an
	 * ordinary classification method or an information theory approach
	 * 
	 * @return
	 */
	public AbstractCveClassifier getCveClassifier() {
		return myClassifierList.get(0);
	}

	/**
	 * get VDO labels and return a double array that includes the
	 * mean/minimum/maximum and standard deviation of the CVSS scores in NVD
	 * matching with these labels
	 * 
	 * @param predictionsForVuln
	 * @return
	 */
	private double[] getCvssScoreFromVdoLabels(Map<String, ArrayList<String[]>> predictionsForVuln) {
		// generate partial CVSS vector from VDO prediction
		String[] cvssVec = partialCvssVectorGenerator.getCVssVector(predictionsForVuln);

		// get CVSS mean/min/max/std dev from Python script
		return cvssScoreCalculator.getCvssScoreJython(cvssVec);
	}

	private String getSeverityLabelFromCvssScore(double cvssScore) {
		String severityLabel = null;
		if (cvssScore < 4)
			severityLabel = "LOW";
		else if (cvssScore <= 6.5)
			severityLabel = "MEDIUM";
		else if (cvssScore < 9)
			severityLabel = "HIGH";
		else
			severityLabel = "CRITICAL";
		return severityLabel;
	}
}
