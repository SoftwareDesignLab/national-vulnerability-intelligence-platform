/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the �Software�), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
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
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.characterizer.divergence.VdoLabelDistribution;
import weka.core.Instance;
import weka.core.Instances;

/**
 * 
 * @author axoeec
 *
 */
public class EntropyBasedCveClassifier extends AbstractCveClassifier {
	protected Logger logger = LogManager.getLogger(getClass().getSimpleName());
	Map<String, VdoLabelDistribution> histograms = new HashMap<String, VdoLabelDistribution>();
	// protected String cveClassifierName = "EntropyBasedCveClassifier";

	enum Method {
		CROSS_ENTROPY, KL_DIVERGENCE, JS_DIVERGENCE;
	}

	Method myMethod = Method.KL_DIVERGENCE;

	public EntropyBasedCveClassifier(String preProcessedTrainingDataFile) {
		this.preProcessedTrainingDataFile = preProcessedTrainingDataFile;

		// load processed training data
		String sCommaSeparatedAttribRows = null;
		try {
			sCommaSeparatedAttribRows = FileUtils.readFileToString(new File(preProcessedTrainingDataFile));
		} catch (IOException e) {
			logger.error("Error loading training data file: " + preProcessedTrainingDataFile + ": " + e.toString());
		}

		sCommaSeparatedCsvData = sCommaSeparatedAttribRows;
		myInstances = getInstacesFromCsvString(sCommaSeparatedAttribRows, useNGrams);

	}

	public EntropyBasedCveClassifier(Instances instances) {
		myInstances = instances;
		myMethod = Method.KL_DIVERGENCE;

	}

	/**
	 * For Cross entropy based classification, training a model translates to
	 * generating feature histograms for all labels
	 */
	@Override
	public void trainMLModel(Instances instances) throws Exception {
		// create label histograms from myInstances

		int numClassValues = instances.classAttribute().numValues();
		for (int valIndex = 0; valIndex < numClassValues; valIndex++) {
			String classValue = instances.classAttribute().value(valIndex);
			histograms.put(classValue, new VdoLabelDistribution(classValue, instances));
		}
		// logger.info("Created " + numClassValues + " feature histograms for VDO labels
		// using " +
		// instances.size() + " instances");
	}

	/**
	 * predict vdo label for an instance (result of a SringToVector filter)
	 */
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

		prediction = classify(currentInstance, bPredictMultiple);
		// logger.info("Predicted: '" + prediction.get(0)[0] + "' with cross-entropy: "
		// +
		// prediction.get(0)[1]);
		return prediction;

	}

	/**
	 * classify according to the min divergence (cross entropy,JSD, KLD?)
	 * 
	 * @param currentInstance
	 * @param bPredictMultiple
	 * @return
	 */
	protected ArrayList<String[]> classify(Instance currentInstance, boolean bPredictMultiple) {
		ArrayList<String[]> prediction = new ArrayList<String[]>();

		double maxCrossEntropy = Double.NEGATIVE_INFINITY;
		double minCrossEntropy = Double.POSITIVE_INFINITY;

		// cve histogram
		VdoLabelDistribution cveHistogram = new VdoLabelDistribution(currentInstance);

		// find closest models with divergence <> Double.POSITIVE_INFINITY
		TreeMap<Double, String> chosenModels = new TreeMap<Double, String>();
		for (VdoLabelDistribution histogram : histograms.values()) {
			double divergenceMetric = Double.POSITIVE_INFINITY;
			if (myMethod == Method.CROSS_ENTROPY)
				divergenceMetric = histogram.calculateCrossEntropy(cveHistogram, true);
			else if (myMethod == Method.KL_DIVERGENCE)
				divergenceMetric = histogram.calculateKLDivergence(cveHistogram);
			else if (myMethod == Method.JS_DIVERGENCE)
				divergenceMetric = histogram.calculateJSDivergence(cveHistogram, true);

			if (divergenceMetric != Double.POSITIVE_INFINITY)
				chosenModels.put(divergenceMetric, histogram.getVdoLabel());
		}

		// chosenModels now has sorted results, smaller divergence first!
		maxCrossEntropy = chosenModels.lastEntry().getKey();
		minCrossEntropy = chosenModels.firstEntry().getKey();

		// convert divergences to normalized confidence values!
		for (Entry<Double, String> entry : chosenModels.entrySet()) {
			double divergence = entry.getKey();
			String label = entry.getValue();
			// double proximity = (maxCrossEntropy - divergence) / maxCrossEntropy;
			// double proximity = (maxCrossEntropy + minCrossEntropy/100 - divergence) /
			// maxCrossEntropy; // to consider largest divergence as well!
			double proximity = (maxCrossEntropy + minCrossEntropy / 100 - divergence); // to consider largest divergence as well!
			prediction.add(new String[] { label, proximity + "" });
		}

		// logger.info("EntropyBasedCveClassifier predicted: " +
		// Arrays.deepToString(prediction.toArray()) +
		// " for " + currentInstance);

		prediction = normalizeList(prediction, true);
		return prediction;

	}

	/**
	 * normalize list
	 */
	private ArrayList<String[]> normalizeList(ArrayList<String[]> prediction, boolean format) {
		double sum = 0;

		// normalize divergences
		for (String[] item : prediction) {
			sum += Double.parseDouble(item[1]);
		}

		for (int i = -0; i < prediction.size(); i++) {
			String[] element = prediction.get(i);
			if (format)
				element[1] = formatter.format(Double.parseDouble(element[1]) / sum);
			else
				element[1] = Double.parseDouble(element[1]) / sum + "";
			prediction.set(i, element);
		}

		return prediction;
	}

	private ArrayList<String[]> oneMinus(ArrayList<String[]> prediction) {
		for (int i = -0; i < prediction.size(); i++) {
			String[] element = prediction.get(i);
			element[1] = (1 - Double.parseDouble(element[1])) + "";
			prediction.set(i, element);
		}
		return prediction;
	}

	@Override
	public void resetClassifier(Object classifier) {
		try {
			this.myMethod = Method.valueOf((String) classifier);
		} catch (Exception e) {
			this.myMethod = Method.KL_DIVERGENCE;
		}
	}

	public HashMap<String, Double> sortHashMap(HashMap<String, Double> hm) {
		// Create a list from elements of HashMap
		List<Map.Entry<String, Double>> list = new ArrayList<Map.Entry<String, Double>>(hm.entrySet());

		// Sort the list
		Collections.sort(list, new Comparator<Map.Entry<String, Double>>() {
			public int compare(Map.Entry<String, Double> o1, Map.Entry<String, Double> o2) {
				return (o1.getValue()).compareTo(o2.getValue());
			}
		});

		// put data from sorted list to hashmap
		HashMap<String, Double> temp = new LinkedHashMap<String, Double>();
		for (Map.Entry<String, Double> aa : list) {
			temp.put(aa.getKey(), aa.getValue());
		}
		return temp;
	}

	@Override
	protected Map<String, Integer> getModelData(String label) {
		return histograms.get(label).getHistogram();
	}

//	@Override
//	public String getCveClassifierName() {
//		return cveClassifierName;
//	}

}
