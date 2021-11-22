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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.characterizer.classifier.AbstractCveClassifier;
import edu.rit.se.nvip.characterizer.classifier.EntropyBasedCveClassifier;
import edu.rit.se.nvip.characterizer.classifier.EntropyThenOrdinaryClassifier;
import edu.rit.se.nvip.characterizer.classifier.OrdinaryCveClassifier;
import edu.rit.se.nvip.characterizer.classifier.OrdinaryThenEntropyClassifier;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;
import weka.classifiers.Classifier;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.functions.SMO;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;

/**
 * 
 * You may run this Experimenter, to measure the performance of NVIP classifiers
 * on a given VDO data set. The data set should be a CSV file with two columns.
 * 
 * The first column named "CVE Description" should include a CVE description.
 * The second column named "Characterization" should include the VDO label (the
 * class label or the noun group value )
 * 
 * ##########################################################################################
 * You need to provide the data set as a command line argument. Example
 * argument: "ImpactMethod.csv" without quotations. This will use the csv file
 * named ImpactMethod under the VDO path. You need to make sure that the file
 * exists under the VDO path, which is the value returned by the
 * getCveCharacterizationTrainingDataDirectory() method in MyProperties.
 * 
 * if you want, you can provide multiple CSV files like
 * "ImpactMethod.csv,Context.csv" (without quotations). Then, the experimenter
 * will output the results for all CSV files provided.
 * 
 * Example argument to run multi-class classification for all noun groups:
 * AttackTheater.csv,Context.csv,ImpactMethod.csv,LogicalImpact.csv,Mitigation.csv
 * 
 * Example argument to run Experimenter for all values under Impact Method
 * group:
 * ImpactMethod-TrustFailure.csv,ImpactMethod-ContextEscape.csv,ImpactMethod-AuthenticationBypass.csv,ImpactMethod-Man-in-the-Middle.csv,ImpactMethod-CodeExecution.csv
 * 
 * 
 * AttackTheater-Remote.csv,AttackTheater-Local.csv,AttackTheater-Physical.csv,AttackTheater-LimitedRmt.csv
 * 
 * LogicalImpact-Read.csv,LogicalImpact-Write.csv,LogicalImpact-ResourceRemoval.csv,LogicalImpact-ServiceInterrupt.csv,LogicalImpact-IndirectDisclosure.csv,LogicalImpact-PrivilegeEscalation.csv
 * ##########################################################################################
 * 
 * @author axoeec
 *
 */
public class RunExperimenter {
	private static Logger logger = LogManager.getLogger(RunExperimenter.class);

	public static void main(String[] args) {
		RunExperimenter experimenter = new RunExperimenter();
		CveCharacterizer cveCharacterizer = null;
		/**
		 * load properties file first
		 */
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		UtilHelper.initLog4j(propertiesNvip);

		// by default use the file in the config file
		String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();

		/**
		 * trainingDataInfo[0] is the root path for the trainign data, and
		 * trainingDataInfo[1] is the list of comma separated CSV files!
		 */
		String csvFilesArgument = null;
		if (args.length > 0)
			csvFilesArgument = args[0];

		String[] csvFileList = csvFilesArgument.split(",");

		for (String csvFile : csvFileList) {
			trainingDataInfo[1] = csvFile;
			logger.info(
					"\n\n\n-----------------------------------------------------------------------------------------------------------------------------------------------\n#######################################\tRunning Experimenter for:  "
							+ csvFile + "\t#######################################\n-----------------------------------------------------------------------------------------------------------------------------------------------");

			cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], "IT", null, false);
			experimenter.runExperimenterForCveCharacterization(cveCharacterizer);

			cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], "ML", null, false);
			experimenter.runExperimenterForCveCharacterization(cveCharacterizer);

		}

	}

	private void runExperimenterForCveCharacterization(CveCharacterizer cveCharacterizer) {

		AbstractCveClassifier myCveClassifier = cveCharacterizer.getCveClassifier();
		UtilHelper.printMemory();
		int[] folds = new int[] { 10 }; // the # of folds
		String approach = "";

		Object[] classifiers = new String[] { "NA" };
		if (cveCharacterizer.getCveClassifier() instanceof EntropyBasedCveClassifier) {
			approach = "IT"; // Information Theory
			/**
			 * Which Information Theory methods?
			 */
			classifiers = new String[] { "KL_DIVERGENCE", "CROSS_ENTROPY" };
			if (cveCharacterizer.getCveClassifier() instanceof EntropyThenOrdinaryClassifier)
				approach = "IT-ML"; // First Information Theory then ML

		} else if (cveCharacterizer.getCveClassifier() instanceof OrdinaryCveClassifier) {
			approach = "ML"; // ML
			Vote vClassifier = new Vote(); // majority vote
			Classifier[] voteClassifiers = new Classifier[] { new SMO(), new NaiveBayes(), new J48(), new RandomForest() };
			vClassifier.setClassifiers(voteClassifiers);

			/**
			 * Which ML classifiers to use?
			 */
			classifiers = new Classifier[] { new SMO(), new NaiveBayes(), new J48(), new RandomForest(), vClassifier };
			// classifiers = new Classifier[] { new SMO() };
			if (cveCharacterizer.getCveClassifier() instanceof OrdinaryThenEntropyClassifier)
				approach = "ML-IT"; // First ML then Information Theory
		}

		int[] classCountsToConsiderForMultiClassPrediction = new int[] { 2 };
		int topClassCountToIncludeInFurtherClassificationRound = 2;
		for (int i = 0; i < classifiers.length; i++) {
			// reset data and classifier
			myCveClassifier.resetClassifier(classifiers[i]);
			String classifierName = cveCharacterizer.getCveClassifier().getCveClassifierName();
			String methodName = classifiers[i].getClass().getSimpleName();
			if (cveCharacterizer.getCveClassifier() instanceof EntropyBasedCveClassifier)
				methodName = (String) classifiers[i];

			methodName = approach + "--> " + methodName;

			for (int j = 0; j < folds.length; j++) {
				logger.info(String.format("%50s", "\n#######################################\t\t\t" + classifierName + "\t-\t" + folds[j] + "folds\t-\t" + methodName));

				double acc;
				// single class
				if (cveCharacterizer.getCveClassifier() instanceof EntropyThenOrdinaryClassifier) {
					for (int topClassCount = 2; topClassCount <= topClassCountToIncludeInFurtherClassificationRound; topClassCount++) {
						((EntropyThenOrdinaryClassifier) cveCharacterizer.getCveClassifier()).setNumOfTopClassesToConsiderForPrediction(topClassCount);
						acc = myCveClassifier.nFoldsPrediction(folds[j], false, 1);
					}

				} else {
					acc = myCveClassifier.nFoldsPrediction(folds[j], false, 1);
				}

				if (!myCveClassifier.getTestMultiClassPrediction())
					continue;

				// multi-class, try different max class counts
				for (int k = 0; k < classCountsToConsiderForMultiClassPrediction.length; k++) {
					acc = myCveClassifier.nFoldsPrediction(folds[j], true, classCountsToConsiderForMultiClassPrediction[k]);

				}

			}

		}

		UtilHelper.printMemory();
	}

}
