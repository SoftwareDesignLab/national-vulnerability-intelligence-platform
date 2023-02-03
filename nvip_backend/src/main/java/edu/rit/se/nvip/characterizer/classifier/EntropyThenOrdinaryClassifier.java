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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import weka.classifiers.trees.J48;
import weka.core.Instance;
import weka.core.Instances;

/**
 * Further classification: After finding divergences, train a model with the top
 * N class labels'data. Those top N labels are the ones that have the closest
 * divergence to the CVE instance we are trying to predict
 * 
 * @author axoeec
 */
public class EntropyThenOrdinaryClassifier extends EntropyBasedCveClassifier {
	private int numOfTopClassesToConsiderForPrediction = 2;
	boolean testMultiClassPrediction = false;

	public EntropyThenOrdinaryClassifier(String sCommaSeparatedAttribRows) {
		super(sCommaSeparatedAttribRows);
	}

	@Override
	protected ArrayList<String[]> classify(Instance currentInstance, boolean bPredictMultiple) {
		ArrayList<String[]> prediction = null;
		try {

			// predict acc to the divergence!
			prediction = super.classify(currentInstance, bPredictMultiple);

			double conf1 = Double.parseDouble(prediction.get(0)[1]);
			double conf2 = Double.parseDouble(prediction.get(1)[1]);
			int sign = (int) (100 * (Math.abs(conf1 - conf2) / conf2));

			if (prediction.size() >= numOfTopClassesToConsiderForPrediction && sign < 20) {

				// retrain a small model including data from the labels that have closest match.
				HashMap<String, Integer> labels = new HashMap<>();
				for (int k = 0; k < numOfTopClassesToConsiderForPrediction; k++) {
					labels.put(prediction.get(k)[0], 0);
				}

				OrdinaryCveClassifier ordinaryCveClassifier = new OrdinaryCveClassifier();
				J48 j48 = new J48();

				ordinaryCveClassifier.resetClassifier(j48);
				Instances newInstances = getSubsetOfInstances(labels, myInstances, currentInstance);
				ordinaryCveClassifier.trainMLModel(newInstances);
				prediction = ordinaryCveClassifier.predict(currentInstance, bPredictMultiple);

				if (logger.isDebugEnabled() && !bPredictMultiple) {
					String pred = prediction.get(0)[0];
					String trueLabel = currentInstance.stringValue(currentInstance.classAttribute());
					String sCorrect = pred.equalsIgnoreCase(trueLabel) ? "[C]" : "[W]";
					int totLabelCount = this.myInstances.classAttribute().numValues();
					logger.info(sCorrect + "\tPredicted '" + pred + "' for '" + trueLabel + "'\tUsed " + newInstances.size() + " training data for " + labels.size() + "[of " + totLabelCount + "] labels: "
							+ Arrays.deepToString(labels.keySet().toArray()));
				}
			}

		} catch (Exception e) {
			logger.error("Error while predicting label for " + currentInstance + ": " + e);
		}

		return prediction;
	}
	
	@Override
	public boolean getTestMultiClassPrediction() {
		return testMultiClassPrediction;
	}

	public void setNumOfTopClassesToConsiderForPrediction(int n) {
		numOfTopClassesToConsiderForPrediction = n;
	}

}
