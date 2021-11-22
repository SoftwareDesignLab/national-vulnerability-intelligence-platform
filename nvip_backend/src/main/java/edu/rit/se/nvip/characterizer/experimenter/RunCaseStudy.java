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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.characterizer.classifier.AbstractCveClassifier;
import weka.core.Instance;
import weka.core.Instances;

/**
 *
 * This class was written to have a case study for NVIP. CVEs after 7/1/2020
 * with a CVE ID > CVE-2020-14000 are queried from NVD CVE Search UI.
 * 
 * Test file is a CSV file (comma separated). First column is CVE, second column
 * is the true label. !!! No comma within column values !!!
 * 
 * Check your path for training and test file:
 * 
 * Training: nounGroupTrainingDataList = new String[] { "ImpactMethod.csv" };
 * 
 * Test: testFile = "../NVIPDataV2/characterization/CaseStudy.csv"
 * 
 * 
 * @author axoeec
 *
 */
public class RunCaseStudy extends AbstractCveClassifier {

	/**
	 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	 * 
	 * update these parameters for your data!
	 * 
	 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	 */
	static String[] trainingDataInfo = new String[] { "../NVIPDataV2/characterization/", "" };

//	String[] nounGroupTrainingDataList = new String[] { "Mitigation_Round2_ASLR.csv",  "Mitigation_Round2_MFA.csv", "Mitigation_Round2_Sandboxed.csv", "Mitigation_Round2_HPKP_HSTS.csv",  "Mitigation_Round2_Physical_Security.csv" };
//	String[] testFile = new String[] { "CaseStudy_ASLR.csv", "CaseStudy_MFA.csv", "CaseStudy_Sandboxed.csv", "CaseStudy_HPKP_HSTS.csv","CaseStudy_Physical_Security.csv" };
//	String[] nounGroupTrainingDataList = new String[] { "ImpactMethod.csv" };
//	String[] testFile = new String[] { "CaseStudy-im.csv" };

//	String[] nounGroupTrainingDataList = new String[] { "AttackTheater.csv" };
//	String[] testFile = new String[] { "CaseStudy-at.csv" };

	String[] nounGroupTrainingDataList = new String[] { "AttackTheater.csv", "ImpactMethod.csv", "Context.csv" };
	String[] testFile = new String[] { "CaseStudy-at.csv", "CaseStudy-im.csv", "CaseStudy-c-2.csv" };

//	String[] nounGroupTrainingDataList = new String[] {"LogicalImpact-ServiceInterrupt.csv","LogicalImpact-Read.csv","LogicalImpact-Write.csv","LogicalImpact-ResourceRemoval.csv","LogicalImpact-IndirectDisclosure.csv","LogicalImpact-PrivilegeEscalation.csv"};
//	String[] testFile = new String[] {"CaseStudy-li-s.csv","CaseStudy-li-r.csv","CaseStudy-li-w.csv","CaseStudy-li-rr.csv","CaseStudy-li-id.csv","CaseStudy-li-p.csv"};
//	

//	String[] nounGroupTrainingDataList = new String[] { "LogicalImpact-ServiceInterrupt.csv", "LogicalImpact-Read.csv", "LogicalImpact-Write.csv",
//			"LogicalImpact-ResourceRemoval.csv", "LogicalImpact-IndirectDisclosure.csv", "LogicalImpact-PrivilegeEscalation.csv", "Mitigation_Round2_ASLR.csv",
//			"Mitigation_Round2_MFA.csv", "Mitigation_Round2_Sandboxed.csv", "Mitigation_Round2_HPKP_HSTS.csv", "Mitigation_Round2_Physical_Security.csv" };
//	String[] testFile = new String[] { "CaseStudy-li-s.csv", "CaseStudy-li-r.csv", "CaseStudy-li-w.csv", "CaseStudy-li-rr.csv", "CaseStudy-li-id.csv", "CaseStudy-li-p.csv",
//			"CaseStudy_ASLR.csv", "CaseStudy_MFA.csv", "CaseStudy_Sandboxed.csv", "CaseStudy_HPKP_HSTS.csv", "CaseStudy_Physical_Security.csv" };

	// change multiClassMultiChance to true, if you want to see the second best
	// prediction for each CVE!
	boolean multiLabelClassification = true; // set to true for multi-label tests
	static boolean multiClassMultiChance = false;

	/**
	 * if the confidence of the first and second predictions are close (difference
	 * <0.05), then consider second prediction while calculating performance
	 * metrics.
	 */
	boolean considerConfidenceProximity = false;
	double confidenceProximityThreshold = 0.1;

	HashMap<String, int[]> labelCountMap = null;
	HashMap<String, Integer> labelClassCountMap = null;
	Map<String, List<String>> methodScoreMap = null;
	int nMaxNumOfClassesToPredict = 2;

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		RunCaseStudy testModel = new RunCaseStudy();

		testModel.testApproach(trainingDataInfo, multiClassMultiChance);
	}

	/**
	 * init score map
	 * 
	 * @param itMethodList
	 * @param mlMethodList
	 * @return
	 */
	private Map<String, List<String>> initScoreMap(String[] itMethodList, String[] mlMethodList) {
		Map<String, List<String>> currentScoreMap = new HashMap<String, List<String>>();

		for (int i = 0; i < itMethodList.length; i++) {
			currentScoreMap.put(itMethodList[i], new ArrayList<String>());
		}

		for (int i = 0; i < mlMethodList.length; i++) {
			currentScoreMap.put(mlMethodList[i], new ArrayList<String>());
		}

		return currentScoreMap;
	}

	/**
	 * Case Study: train and test for each method.
	 * 
	 * @param trainingDataInfo
	 */
	private void testApproach(String[] trainingDataInfo, boolean multiClassMultiChance) {

		// String[] nounGroupTrainingDataList = new String[] { "AttackTheater.csv",
		// "Context.csv",
		// "ImpactMethod.csv", "LogicalImpact.csv", "Mitigation.csv" };

		// String[] nounGroupTrainingDataList = new String[] { "AttackTheater.csv",
		// "ImpactMethod.csv"};

		// String[] nounGroupTrainingDataList = new String[] {
		// "ImpactMethod-TrustFailure.csv",
		// "ImpactMethod-ContextEscape.csv", "ImpactMethod-AuthenticationBypass.csv",
		// "ImpactMethod-Man-in-the-Middle.csv", "ImpactMethod-CodeExecution.csv" };
		String[] itMethodList = new String[] { "KL_DIVERGENCE", "CROSS_ENTROPY" };
		String[] mlMethodList = new String[] { "SVM", "NB", "DT", "RF", "Vote" };

		String approach = null;
		String method = null;

		if (nounGroupTrainingDataList.length != testFile.length) {
			System.out.println("Error in the input files!");
			System.exit(1);
		}

		methodScoreMap = initScoreMap(itMethodList, mlMethodList);

		// for each training data file
		for (int index = 0; index < nounGroupTrainingDataList.length; index++) {

			String ngTestFile = trainingDataInfo[0] + testFile[index];

			////////////////////////////////////////// Test file /////////////////////////
			Map<String, Integer> trueCountMap = new HashMap<String, Integer>();

			/**
			 * load test file. Test file is a csv file (comma separated). First column is
			 * CVE, second column is the true label.
			 */
			List<String> lineList = new ArrayList<String>();
			lineList = readLines(ngTestFile);
			lineList.remove(0); // skip header!

			/**
			 * get CVEs and true labels
			 */
			List<String> cveList = new ArrayList<String>();
			List<String> trueLabelList = new ArrayList<String>();
			for (String line : lineList) {
				String[] parts = line.split(",");
				cveList.add(parts[0]);
				trueLabelList.add(parts[1]);
			}

			// print test file CVEs,
			System.out.println("\n\n################## Test File: " + testFile);

			for (int j = 0; j < cveList.size(); j++) {
				System.out.println("Cve #: " + (j + 1) + ": " + cveList.get(j));
			}
			////////////////////////////////////////// Test file /////////////////////////

			String nounGroup = nounGroupTrainingDataList[index];
			trainingDataInfo[1] = nounGroup; // set noun group training file
			System.out.println("\n\n################## Testing noun group: " + nounGroup);

			Instances myInstances = null;
			try {
				String labelDistrFile = ngTestFile;
				if (multiLabelClassification)
					labelDistrFile = trainingDataInfo[0] + trainingDataInfo[1];

				String sCommaSeparatedAttribRows = FileUtils.readFileToString(new File(labelDistrFile));
				myInstances = getInstacesFromCsvString(sCommaSeparatedAttribRows, true);
			} catch (IOException e) {
				e.printStackTrace();
			}

			labelClassCountMap = getLabelCounts(myInstances);

			/**
			 * IT methods
			 */
			for (int i = 0; i < itMethodList.length; i++) {

				labelCountMap = getLabels(myInstances); // reset TP,FP,TN,FN

				approach = "IT";
				method = itMethodList[i];
				// train
				CveCharacterizer cveCharacterizer = train(trainingDataInfo, approach, method);

				// test
				int trueCount = 0;
				System.out.println("\n\n################## Testing approach-method: " + approach + ": " + method + " for noun group: " + nounGroup);
				for (int j = 0; j < cveList.size(); j++) {
					String cveDescription = cveList.get(j);
					trueCount += predict(cveCharacterizer, (j + 1), cveDescription, approach, method, multiClassMultiChance, trueLabelList.get(j));
				}
				System.out.println("*********** Testing approach-method: " + approach + ": " + method + " for noun group: " + nounGroup + ", TrueCount: " + trueCount);

				// print label based accuracies
				printLabelBasedMetrics(labelCountMap, multiClassMultiChance, nMaxNumOfClassesToPredict, labelClassCountMap, null);

				trueCountMap.put(method, trueCount);
				methodScoreMap = scoreLabelMetrics(method, labelCountMap, methodScoreMap); // record label based scores
			}

			/**
			 * ML methods
			 */

			for (int i = 0; i < mlMethodList.length; i++) {

				labelCountMap = getLabels(myInstances);// reset TP,FP,TN,FN

				approach = "ML";
				method = mlMethodList[i];

				// train
				CveCharacterizer cveCharacterizer = train(trainingDataInfo, approach, method);

				// test
				int trueCount = 0;
				System.out.println("\n\n################## Testing approach-method: " + approach + ": " + method + " for noun group: " + nounGroup);
				for (int j = 0; j < cveList.size(); j++) {
					String cveDescription = cveList.get(j);
					trueCount += predict(cveCharacterizer, (j + 1), cveDescription, approach, method, multiClassMultiChance, trueLabelList.get(j));
				}
				System.out.println("*********** Testing approach-method: " + approach + ": " + method + " for noun group: " + nounGroup + ", TrueCount: " + trueCount);

				// print label based accuracies
				printLabelBasedMetrics(labelCountMap, multiClassMultiChance, nMaxNumOfClassesToPredict, labelClassCountMap, null);

				trueCountMap.put(method, trueCount);

				methodScoreMap = scoreLabelMetrics(method, labelCountMap, methodScoreMap); // record label based scores
			}

			// print counts and %
			System.out.println("\n\n################## True Count & Accuracy for: " + nounGroup + ", multiClassMultiChance: " + multiClassMultiChance);
			DecimalFormat df = new DecimalFormat("#.##");
			for (int i = 0; i < itMethodList.length; i++) {
				String key = itMethodList[i];
				System.out.println("Method: " + key + ", Count: " + trueCountMap.get(key) + ", %: " + df.format(trueCountMap.get(key) * 1.0 / lineList.size()));
			}
			for (int i = 0; i < mlMethodList.length; i++) {
				String key = mlMethodList[i];
				System.out.println("Method: " + key + ", Count: " + trueCountMap.get(key) + ", %: " + df.format(trueCountMap.get(key) * 1.0 / lineList.size()));
			}
		} // for (int index = 0; index < nounGroupTrainingDataList.length; index++)

		// print precision, recall, f-measure
		System.out.println("\n\n################## Precision, Recall, F-measure for ALL NOUN GROUPS!");
		for (int i = 0; i < itMethodList.length; i++) {
			String key = itMethodList[i];
			System.out.println(String.format("%20s", key) + ",Precision,Recall,F-Measure");
			List<String> scores = methodScoreMap.get(key);
			for (String scoreLine : scores)
				System.out.println(scoreLine);
		}
		for (int i = 0; i < mlMethodList.length; i++) {
			String key = mlMethodList[i];
			System.out.println(String.format("%20s", key) + ",Precision,Recall,F-Measure");
			List<String> scores = methodScoreMap.get(key);
			for (String scoreLine : scores)
				System.out.println(scoreLine);
		}
	}

	/**
	 * train a characterizer
	 * 
	 * @param trainingDataInfo
	 * @param approach
	 * @param method
	 * @return
	 */
	private CveCharacterizer train(String[] trainingDataInfo, String approach, String method) {
		return new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], approach, method, false);
	}

	/**
	 * test characterizer for a CVE
	 * 
	 * @param cveCharacterizer
	 * @param cveDesc
	 * @param approach
	 * @param method
	 */
	private int predict(CveCharacterizer cveCharacterizer, int cveNum, String cveDesc, String approach, String method, boolean multiClassMultiChance, String trueLabel) {
		int isTrue = 0;
		ArrayList<String[]> prediction = cveCharacterizer.characterizeCve(cveDesc, true);
		String predictedLabel = null;
		for (int i = 0; i < 2 && i < prediction.size(); i++) {
			String[] pred = prediction.get(i);
			predictedLabel = pred[0];
			String confidence = pred[1];
			boolean isCorrect = trueLabel.contains(predictedLabel);
			String correct = isCorrect ? "" : "#";

			System.out.println(correct + "Cve #: " + cveNum + "\t" + approach + "\t" + method + "\tPredicted/True Label: " + predictedLabel + "[" + trueLabel + "]\tConf:" + confidence);

			/**
			 * check the second best prediction and confidence.
			 */
			String nextPrediction = "na";
			String nextConfidence = "na";
			if (isCorrect) {
				isTrue = 1;
				break;
			} else if ((i == 0) && (i + 1) < prediction.size()) {
				nextPrediction = prediction.get(i + 1)[0];
				nextConfidence = prediction.get(i + 1)[1];

				if ((Math.abs(Double.parseDouble(confidence) - Double.parseDouble(nextConfidence)) <= confidenceProximityThreshold) && !trueLabel.contains(predictedLabel) && trueLabel.contains(nextPrediction)) {
					System.out.println("\n******** ATTENTION: The second prediction has the same confidence is CORRECT for CVE #: " + cveNum + "!" + "\t\tNext Prediction:[" + nextPrediction + "," + nextConfidence + "]");
					if (considerConfidenceProximity) {
						isTrue = 1;
						predictedLabel = nextPrediction;

					}
				}
			}

			if (!multiClassMultiChance)
				break;
		}

		// increment tp,fp,tn.fn
		// String predictedLabel = prediction.get(0)[0];
		if (isTrue == 1) {
			labelCountMap = incrementTrueCount(trueLabel, predictedLabel, labelCountMap); //
		} else {
			labelCountMap = incrementFalseCount(trueLabel, predictedLabel, labelCountMap);//
		}

		return isTrue;
	}

	private List<String> readLines(String filename) {
		ArrayList<String> result = new ArrayList<>();

		try {
			try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
				while (br.ready()) {
					result.add(br.readLine());
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	@Override
	protected void trainMLModel(Instances instances) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	protected ArrayList<String[]> predict(Instance currentInstance, boolean bPredictMultiple) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void resetClassifier(Object classifier) {
		// TODO Auto-generated method stub

	}

	@Override
	protected Map<String, Integer> getModelData(String label) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Add precision, recall and f-measure of each predicted label
	 * 
	 * @param method:         KLd,SVM etc.
	 * @param labelCountMap:  Previous scores
	 * @param currentScoreMap
	 * @return
	 */
	private Map<String, List<String>> scoreLabelMetrics(String method, HashMap<String, int[]> labelCountMap, Map<String, List<String>> currentScoreMap) {

		List<String> scoreList = currentScoreMap.get(method);

		for (String label : labelCountMap.keySet()) {
			double prec = labelCountMap.get(label)[0] * 1.0 / (labelCountMap.get(label)[0] + labelCountMap.get(label)[1]);
			double recall = labelCountMap.get(label)[0] * 1.0 / (labelCountMap.get(label)[0] + labelCountMap.get(label)[3]);
			double f1 = 2 * (prec * recall) / (prec + recall);

			if (Double.isNaN(prec) || Double.isNaN(recall) || Double.isNaN(f1)) { // if no f-measure score?
				f1 = 0;
			}

			String labelScore = (String.format("%20s", label) + "," + formatter.format(prec) + "," + formatter.format(recall) + "," + formatter.format(f1));

			boolean recordScore = true;
//			if (!multiLabelClassification)
//				if (label.contains("0"))
//					recordScore = false; // do not record for negative class

			if (recordScore)
				scoreList.add(labelScore);
		}
		currentScoreMap.put(method, scoreList);
		return currentScoreMap;
	}

}
