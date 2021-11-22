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
package edu.rit.se.nvip.characterizer.classifier;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import weka.classifiers.Classifier;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.functions.SMO;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;
import weka.core.Instance;
import weka.core.Instances;

/**
 *
 * @author axoeec
 *
 */
public class OrdinaryCveClassifier extends AbstractCveClassifier {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * Sometimes the confidence for a predicted label could be 1.0, but the
	 * prediction might be wrong!! If that is the case for some predictions, then
	 * you will not be able to see 100% accuracy for binary predictions with
	 * MULTI-CHANCE option, because MIN_CONFIDENCE_THRESHOLD < 1!
	 */
	protected final double MIN_CONFIDENCE_THRESHOLD = 0.60;

	protected Instances myInstances = null;
	protected Classifier classifier = new RandomForest();

	public OrdinaryCveClassifier() {
		Vote vClassifier = new Vote();
		Classifier[] voteClassifiers = new Classifier[] { new RandomForest(), new SMO(), new NaiveBayes(), new J48() };
		vClassifier.setClassifiers(voteClassifiers);
		classifier = vClassifier;
	}

	public OrdinaryCveClassifier(Classifier classifier, String preProcessedTrainingDataFile) {
		this.preProcessedTrainingDataFile = preProcessedTrainingDataFile;

		// load processed training data
		String sCommaSeparatedAttribRows = null;
		try {
			sCommaSeparatedAttribRows = FileUtils.readFileToString(new File(preProcessedTrainingDataFile));
		} catch (IOException e) {
			logger.error("Error loading training data file: " + preProcessedTrainingDataFile + ": " + e.toString());
		}

		this.sCommaSeparatedCsvData = sCommaSeparatedAttribRows;
		this.myInstances = getInstacesFromCsvString(sCommaSeparatedAttribRows, useNGrams);
		this.classifier = classifier;
	}

	@Override
	public void trainMLModel(Instances instances) throws Exception {
		myInstances = instances;
		classifier.buildClassifier(instances);

		String info = "A CVE classifier [" + this.classifier.getClass().getSimpleName() + "] is trained with " + instances.numInstances() + " instances and " + instances.numAttributes() + " attributes!";
		// logger.info(info);
	}

	@Override
	public ArrayList<String[]> predict(Instance currentInstance, boolean bPredictMultiple) {
		ArrayList<String[]> prediction = new ArrayList<String[]>();
		if (currentInstance.numAttributes() != myInstances.numAttributes()) {
			logger.error("Error! The instances in the data set has " + myInstances.numAttributes() + " attribs, but the instance you are trying to predict has " + currentInstance.numAttributes()
					+ " atribs?\nNo prediction could be done for this instance: " + currentInstance.toString());

			return prediction;
		}

		if (myInstances.numClasses() == 1) {
			// we have a unary class, so no need to make a prediction
			prediction.add(new String[] { myInstances.classAttribute().value(0), "1" });
			return prediction;
		}

		prediction = classify(classifier, currentInstance, bPredictMultiple);

		return prediction;
	}

	/**
	 * classify given instance based on the underlying approach
	 * 
	 * @param classifier
	 * @param currentInstance
	 * @param bPredictMultiple
	 * @return
	 */
	protected ArrayList<String[]> classify(Classifier classifier, Instance currentInstance, boolean bPredictMultiple) {
		ArrayList<String[]> prediction = new ArrayList<String[]>();
		try {
			double[] predictProb = classifier.distributionForInstance(currentInstance); // get the prediction probabilities
			if (bPredictMultiple) {
				// sort ascending
				Map<String, Integer> indexes = new HashMap<String, Integer>();
				for (int i = 0; i < predictProb.length; i++)
					indexes.put(formatter.format(predictProb[i]), i);

				Arrays.sort(predictProb);

				// get predictions with significant confidence!
				double sum = 0;

				for (int index = predictProb.length - 1; index >= 0; index--) {
					String prob = formatter.format(predictProb[index]); // Get the probability.
					int labelIndex = indexes.get(prob);
					String label = myInstances.attribute(0).value(labelIndex); // Get class label.
					prediction.add(new String[] { label, prob });
					sum += predictProb[index];
					if (sum >= MIN_CONFIDENCE_THRESHOLD)
						break;
				}
			} else {

				double predictedValue = classifier.classifyInstance(currentInstance); // predict class
				String probability = formatter.format(predictProb[(int) predictedValue]); // get probability of our target
				String label = myInstances.classAttribute().value((int) predictedValue);
				prediction.add(new String[] { label, probability });
			}
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return prediction;
	}

	@Override
	public void resetClassifier(Object classifier) {
		this.classifier = (Classifier) classifier;

	}

	@Override
	protected Map<String, Integer> getModelData(String label) {
		// not applicable
		return null;
	}

//	@Override
//	public String getCveClassifierName() {
//		return cveClassifierName;
//	}

}
