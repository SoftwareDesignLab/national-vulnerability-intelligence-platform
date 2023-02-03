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
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import weka.classifiers.Classifier;
import weka.core.Instance;
import weka.core.Instances;

/**
 * 
 * @author axoeec
 *
 */
public class OrdinaryThenEntropyClassifier extends OrdinaryCveClassifier {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	int CONFIDENCE_DIFFERENCE_THRESHOLD = 20;

	boolean testMultiClassPrediction = false;

	public OrdinaryThenEntropyClassifier(Classifier classifier, String preProcessedTrainingDataFile) {

		this.preProcessedTrainingDataFile = preProcessedTrainingDataFile;

		// load processed training data
		String sCommaSeparatedAttribRows = null;
		try {
			sCommaSeparatedAttribRows = FileUtils.readFileToString(new File(preProcessedTrainingDataFile));
		} catch (IOException e) {
			logger.error("Error loading training data file: " + preProcessedTrainingDataFile + ": " + e);
		}

		this.sCommaSeparatedCsvData = sCommaSeparatedAttribRows;
		this.myInstances = getInstacesFromCsvString(sCommaSeparatedAttribRows, useNGrams);
		this.classifier = classifier;
	}

	@Override
	public void trainMLModel(Instances instances) throws Exception {
		myInstances = instances;
		classifier.buildClassifier(instances);

	}

	@Override
	public ArrayList<String[]> predict(Instance currentInstance, boolean bPredictMultiple) {
		ArrayList<String[]> prediction = new ArrayList<>();
		if (currentInstance.numAttributes() != myInstances.numAttributes()) {
			logger.error("Error! The instances in the data set has " + myInstances.numAttributes() + " attribs, but the instance you are trying to predict has " + currentInstance.numAttributes()
					+ " atribs?\nNo prediction could be done for this instance: " + currentInstance);

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

			prediction = super.classify(classifier, currentInstance, true);
			int differenceOfConfidences = Integer.MAX_VALUE;
			if (prediction.size() > 1) { // the classifier might be 100% sure, and you may have only one prediction!
				double conf1 = Double.parseDouble(prediction.get(0)[1]);
				double conf2 = Double.parseDouble(prediction.get(1)[1]);
				differenceOfConfidences = (int) (100 * (Math.abs(conf1 - conf2) / conf2));
			}

			if (prediction.size() >= 2 && differenceOfConfidences < CONFIDENCE_DIFFERENCE_THRESHOLD) {

				// get class labels for best two predictions
				HashMap<String, Integer> indexes = new HashMap<>();
				for (int i = 0; i < 2; i++)
					indexes.put(prediction.get(i)[0], i);

				// get instances for two best predicted labels
				Instances newInstances = getSubsetOfInstances(indexes, myInstances, currentInstance);
				EntropyBasedCveClassifier cveClassifier = new EntropyBasedCveClassifier(myInstances);
				cveClassifier.trainMLModel(newInstances);
				prediction = cveClassifier.predict(currentInstance, false);

			} else {
				// leave only the best one
				for (int i = prediction.size() - 1; i > 0; i--)
					prediction.remove(i);
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

	@Override
	public boolean getTestMultiClassPrediction() {
		return testMultiClassPrediction;
	}

}
