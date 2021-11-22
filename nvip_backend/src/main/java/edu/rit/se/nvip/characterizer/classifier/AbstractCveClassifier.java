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

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.InstanceComparator;
import weka.core.Instances;
import weka.core.converters.CSVLoader;
import weka.core.tokenizers.NGramTokenizer;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.AddValues;
import weka.filters.unsupervised.attribute.NominalToString;
import weka.filters.unsupervised.attribute.StringToWordVector;

/**
 * 
 * 
 * @author axoeec
 *
 */
public abstract class AbstractCveClassifier {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	protected NumberFormat formatter = new DecimalFormat("#0.000");
	protected String sCommaSeparatedCsvData = null;
	protected Instances myInstances;
	protected boolean testMultiClassPrediction = true;
	protected String cveClassifierName = "AbstractCveClassifier";
	protected String preProcessedTrainingDataFile = null;

	protected boolean useNGrams = true; // use NGrams while applying StringToWrodVector filter?

	/**
	 * train a ML model based on the underlying classification approach. Use the
	 * data provided
	 * 
	 * @param instances
	 * @throws Exception
	 */
	protected abstract void trainMLModel(Instances instances) throws Exception;

	protected abstract ArrayList<String[]> predict(Instance currentInstance, boolean bPredictMultiple);

	public abstract void resetClassifier(Object classifier);

	protected abstract Map<String, Integer> getModelData(String label);

	/**
	 * train a ML model based on the underlying classification approach. Use the
	 * data that you already have!
	 * 
	 * @return
	 */

	public void trainMLModel() {
		String info = "";
		try {
			trainMLModel(myInstances);
		} catch (Exception e) {
			info = "Oops, an error occured! Check your training data, Detail: " + e.toString();
			logger.error(info);
		}
	}

	/**
	 * Predict the label for <sCommaSeparatedAttribs>
	 * 
	 * @param sCommaSeparatedAttribs
	 * @param bPredictMultiple
	 * @return
	 */
	public ArrayList<String[]> predict(String sCommaSeparatedAttribs, boolean bPredictMultiple) {
		ArrayList<String[]> prediction = new ArrayList<String[]>();
		try {
			Instance currentInstance = createInstanceFromCommaSeparatedAttribs(sCommaSeparatedAttribs, true);

			prediction = predict(currentInstance, bPredictMultiple);
		} catch (Exception e) {
			logger.error("Error during predict() instance count:" + myInstances.numInstances(), e);
			e.printStackTrace();
		}
		return prediction;
	}

	/**
	 * This methods creates a map to keep track of TP,FP,TN,FNs for each label
	 * 
	 * @param instances
	 * @return
	 */
	protected HashMap<String, int[]> getLabels(Instances instances) {
		HashMap<String, int[]> map = new HashMap<String, int[]>();
		int classCount = instances.classAttribute().numValues();
		for (int i = 0; i < classCount; i++) {
			String label = instances.classAttribute().value(i);
			map.put(label, new int[] { 0, 0, 0, 0 });
		}

		return map;
	}

	/**
	 * get clas label counts
	 * 
	 * @param instances
	 * @return
	 */
	protected HashMap<String, Integer> getLabelCounts(Instances instances) {

		HashMap<String, Integer> map = new HashMap<String, Integer>();
		int classCount = instances.classAttribute().numValues();
		for (int i = 0; i < classCount; i++) {
			String label = instances.classAttribute().value(i);
			map.put(label, 0);
		}
		for (Instance instance : instances) {
			String label = instance.stringValue(instance.classAttribute());
			int count = map.get(label);
			count++;
			map.put(label, count);
		}

		return map;
	}

	/**
	 * increment true positive count for this label! Counts array: TP,FP,TN,FN
	 * 
	 * @param label
	 * @param map
	 * @return
	 */
	protected HashMap<String, int[]> incrementTrueCount(String trueLabel, String predictedLabel, HashMap<String, int[]> map) {

		for (String keyLabel : map.keySet()) {
			int[] counts = map.get(keyLabel);
			// a TP for label X is a TN for label Y
			if (keyLabel.equalsIgnoreCase(predictedLabel))
				counts[0] += 1;
			else
				counts[2] += 1;
			map.put(keyLabel, counts);
		}

		return map;
	}

	/**
	 * increment false positive count for this label! Counts array: TP,FP,TN,FN
	 * 
	 * @param label
	 * @param map
	 * @return
	 */
	protected HashMap<String, int[]> incrementFalseCount(String trueLabel, String predictedLabel, HashMap<String, int[]> map) {
		// a FP for label X is a FN for label Y
		for (String keyLabel : map.keySet()) {
			int[] counts = map.get(keyLabel);
			if (keyLabel.equalsIgnoreCase(predictedLabel))
				counts[1] += 1;
			else {
				if (keyLabel.equalsIgnoreCase(trueLabel))
					counts[3] += 1;
			}
			map.put(keyLabel, counts);
		}

		return map;
	}

	/**
	 * get average metrics: accuracy, precision, recall and f-measure
	 * 
	 * Counts array: TP,FP,TN,FN
	 * 
	 * @param map
	 * @return
	 */
	protected double[] getAvgMetrics(HashMap<String, int[]> labelCountMap, HashMap<String, Integer> labelClassCountMap) {
		double precision = 0, recall = 0, f1 = 0;
		double totPrecision = 0, totRecall = 0, totF1 = 0;

		try {
			int tp = 0, fp = 0, tn = 0, fn = 0;
			int totInstanceCount = 0;
			for (String key : labelCountMap.keySet()) {
				int[] counts = labelCountMap.get(key);
				tp = counts[0];
				fp = counts[1];
				tn = counts[2];
				fn = counts[3];

				int classCount = labelClassCountMap.get(key);
				totInstanceCount += classCount;

				precision = tp * 1.0 / (tp + fp);
				recall = tp * 1.0 / (tp + fn);
				f1 = (2 * (precision * recall) / (precision + recall));

				totPrecision += precision * classCount;
				totRecall += recall * classCount;
				totF1 += f1 * classCount;
			}

			precision = totPrecision / totInstanceCount;
			recall = totRecall / totInstanceCount;
			f1 = totF1 / totInstanceCount;

		} catch (Exception e) {
			logger.error(e.toString());
		}
		return new double[] { precision, recall, f1 };

	}

	private HashMap<String, int[]> resetMap(HashMap<String, int[]> map) {
		for (String key : map.keySet()) {
			int[] counts = map.get(key);
			counts[0] = 0;
			counts[1] = 0;
			map.put(key, counts);
		}
		return map;
	}

	/**
	 * get label index map
	 * 
	 * @param labelCountMap
	 * @return
	 */
	private Map<String, Integer> createLabelIndexMap(HashMap<String, int[]> labelCountMap) {
		Map<String, Integer> labelIndexMap = new HashMap<String, Integer>();
		int index = 0;
		for (String key : labelCountMap.keySet()) {
			labelIndexMap.put(key, index);
			index++;
		}
		return labelIndexMap;

	}

	/**
	 * Test leave one out with single and multi-class prediction options for N-folds
	 * and return classification accuracy
	 * 
	 * @param folds
	 * @param bPredictMultiple
	 * @param nMaxNumOfClassesToPredict
	 * @return
	 */
	public double nFoldsPrediction(int folds, boolean bPredictMultiple, int nMaxNumOfClassesToPredict) {
		double overallAccuracy = 0.0;
		double totAccuracy = 0;
		HashMap<String, int[]> labelCountMap = null;
		HashMap<String, Integer> labelClassCountMap = null;
		Map<String, Double> labelMapJaccard = new HashMap<String, Double>();
		try {
			// reload data
			myInstances = getInstacesFromCsvString(sCommaSeparatedCsvData, useNGrams);

			labelCountMap = getLabels(myInstances);
			labelClassCountMap = getLabelCounts(myInstances);

			Map<String, Integer> labelIndexMap = createLabelIndexMap(labelCountMap);
			int[][] confMatrix = new int[labelIndexMap.size()][labelIndexMap.size()];

			Random rand = new Random(1); // create seeded number generator
			Instances randData = new Instances(myInstances); // create copy of original data
			randData.randomize(rand); // randomize data with number generator

			randData.stratify(folds);

			for (int n = 0; n < folds; n++) {
				Instances train = randData.trainCV(folds, n, rand);
				Instances test = randData.testCV(folds, n);

				trainMLModel(train);

				int trueCount = 0, falseCount = 0;
				// predict instances
				for (int i = 0; i < test.size(); i++) {
					Instance instance = test.get(i);
					ArrayList<String[]> prediction = predict(instance, bPredictMultiple);

					String predictedLabel = null;
					String trueLabel = instance.stringValue(instance.classAttribute());
					if (bPredictMultiple) {
						boolean isTrue = false;
						predictedLabel = prediction.get(0)[0];
						for (int j = 0; j < prediction.size(); j++)
							if (j == nMaxNumOfClassesToPredict)
								break;
							else if (trueLabel.equalsIgnoreCase(prediction.get(j)[0])) {
								isTrue = true;
								predictedLabel = prediction.get(j)[0];
							}

						if (isTrue) {
							trueCount++;
							labelCountMap = incrementTrueCount(trueLabel, predictedLabel, labelCountMap); //
						} else {
							falseCount++;
							labelCountMap = incrementFalseCount(trueLabel, predictedLabel, labelCountMap);//
						}

					} else {
						// single prediction
						predictedLabel = prediction.get(0)[0];
						if (trueLabel.equalsIgnoreCase(predictedLabel)) {
							trueCount++;
							labelCountMap = incrementTrueCount(trueLabel, predictedLabel, labelCountMap); //
						} else {
							falseCount++;
							labelCountMap = incrementFalseCount(trueLabel, predictedLabel, labelCountMap);//
						}

					}
					// increment conf matrix entry based on the true/predicted labels
					confMatrix[labelIndexMap.get(trueLabel)][labelIndexMap.get(predictedLabel)]++;

				}
				double accuracy = trueCount * 100.0 / (trueCount + falseCount);

				totAccuracy += accuracy;

			} // for (int n = 0; n < folds; n++) {

			overallAccuracy = Double.parseDouble(formatter.format(totAccuracy / folds));

			labelMapJaccard = calculateJaccardMetric(labelIndexMap, confMatrix);
		} catch (Exception e) {
			logger.error(e.toString());
		}

		// print label based accuracies
		double avgAcc = Double.parseDouble(formatter.format(printLabelBasedMetrics(labelCountMap, bPredictMultiple, nMaxNumOfClassesToPredict, labelClassCountMap, labelMapJaccard)[0]));

		// return overallAccuracy;
		return avgAcc;
	}

	/**
	 * print Jaccard
	 * 
	 * @param labelIndexMap
	 * @param confMatrix
	 */
	private Map<String, Double> calculateJaccardMetric(Map<String, Integer> labelIndexMap, int[][] confMatrix) {
		Map<String, Double> labelMapJaccard = new HashMap<String, Double>();

		if (labelIndexMap.size() < 3) // for multi label only
			return labelMapJaccard;

		StringBuffer sJaccard = new StringBuffer("Jaccard Distances:\n");
		for (String label : labelIndexMap.keySet()) {
			int index = labelIndexMap.get(label);
			int totRow = 0;
			for (int i = 0; i < labelIndexMap.size(); i++)
				totRow += confMatrix[index][i];

			int totCol = 0;
			for (int i = 0; i < labelIndexMap.size(); i++) {
				if (i != index)
					totCol += confMatrix[i][index];
			}

			double jaccard = confMatrix[index][index] * 1.0 / (totRow + totCol);

			labelMapJaccard.put(label, jaccard);
		}

		// logger.info(sJaccard);
		return labelMapJaccard;

	}

	/**
	 * Counts array: TP,FP,TN,FN
	 * 
	 * @param labelCountMap
	 * @param bPredictMultiple
	 * @param nMaxNumOfClassesToPredict
	 * @return
	 */
	protected double[] printLabelBasedMetrics(HashMap<String, int[]> labelCountMap, boolean bPredictMultiple, int nMaxNumOfClassesToPredict, HashMap<String, Integer> labelClassCountMap, Map<String, Double> labelMapJaccard) {
		String labelBasedMetrics = "";
		double[] metrics = getAvgMetrics(labelCountMap, labelClassCountMap);
		for (String label : labelCountMap.keySet()) {
			double prec = labelCountMap.get(label)[0] * 1.0 / (labelCountMap.get(label)[0] + labelCountMap.get(label)[1]);
			double recall = labelCountMap.get(label)[0] * 1.0 / (labelCountMap.get(label)[0] + labelCountMap.get(label)[3]);
			double f1 = 2 * (prec * recall) / (prec + recall);
			double jacc = Double.NaN;
			if (labelMapJaccard != null)
				jacc = labelMapJaccard.get(label);
			labelBasedMetrics += (String.format("%20s", label) + "\t-->\t" + formatter.format(prec) + "," + formatter.format(recall) + "," + formatter.format(f1) + "," + formatter.format(jacc) + "\n");
		}
		String sAvgAcc = formatter.format(metrics[0]) + "," + formatter.format(metrics[1]) + "," + formatter.format(metrics[2]);
		labelBasedMetrics += "--------------------------------------------------\n";
		String singleOrMulti = bPredictMultiple ? "Multi-chance[" + nMaxNumOfClassesToPredict + "]" : "Single-class";
		labelBasedMetrics += (String.format("%20s", singleOrMulti));
		labelBasedMetrics += ("\t-->\t" + sAvgAcc + "\n");
		logger.info("\n" + labelBasedMetrics);
		return metrics;
	}

	/**
	 * get instances that have a label in <labels> hash for training. You must
	 * exclude current test instance <excludedTestInstance>
	 * 
	 * @param labels
	 * @param myInstances
	 * @return
	 */
	protected Instances getSubsetOfInstances(HashMap<String, Integer> labels, Instances myInstances, Instance excludedTestInstance) {
		Instances instances = new Instances(myInstances, -1);
		InstanceComparator instanceComparator = new InstanceComparator();
		for (Instance instance : myInstances)
			if (labels.containsKey(instance.stringValue(instance.classAttribute())) && (instanceComparator.compare(instance, excludedTestInstance) != 0))
				instances.add(instance);
		return instances;
	}

	/**
	 * get words from instance, ignore class, start from index 1!
	 * 
	 * @param instance
	 * @return
	 */
	protected String getWordsFromInstance(Instance instance) {
		StringBuffer features = new StringBuffer();
		for (int i = 1; i < instance.numAttributes(); i++) {
			int count = (int) instance.value(i);
			for (int j = 0; j < count; j++) {
				features.append(instance.attribute(i).name()); // add count words
				features.append(" ");
			}
		}

		return "\t" + features.toString();
	}

	/**
	 * create a weka instance from comma separated string
	 * 
	 * @param sCommaSeparatedAttribRows
	 * @param useNGrams                 TODO
	 * @return
	 */
	protected Instances getInstacesFromCsvString(String sCommaSeparatedAttribRows, boolean useNGrams) {

		try {
			InputStream stream = new ByteArrayInputStream(sCommaSeparatedAttribRows.getBytes());

			// load CSV structure
			CSVLoader loader = new CSVLoader();
			loader.setSource(stream);
			// the first column is the description and the second one is the label!!
			loader.setStringAttributes("1");
			loader.setNominalAttributes("2");
			myInstances = loader.getDataSet();

			myInstances.setClassIndex(myInstances.numAttributes() - 1); // here the index starts from 0!

			// Nominal to String
			myInstances = nominalToStringFilter(myInstances);

			// String To Word Vector
			myInstances = stringToWordVectorFilter(myInstances, useNGrams);

			// log data for trace/debug
			dumpData(preProcessedTrainingDataFile + ".arff");
		} catch (IOException e) {
			logger.error(e.toString());
		}

		return myInstances;
	}

	/**
	 * Nominal To String Filter
	 * 
	 * @param myInstances
	 * @return
	 */
	private Instances nominalToStringFilter(Instances myInstances) {
		try {
			NominalToString nomToStringFilter = new NominalToString();
			nomToStringFilter.setAttributeIndexes("first"); // assuming the description if the first column
			nomToStringFilter.setInputFormat(myInstances);
			myInstances = Filter.useFilter(myInstances, nomToStringFilter);
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return myInstances;

	}

	/**
	 * string To Word Vector Filter
	 * 
	 * @param myInstances
	 * @param useNGrams   TODO
	 * @return
	 */
	private Instances stringToWordVectorFilter(Instances myInstances, boolean useNGrams) {
		try {
			int attribCount = myInstances.numAttributes();
			StringToWordVector stringToWordFilter = new StringToWordVector();

			/**
			 * When we use entropy, we already calculate probability, so do not need term
			 * frequency(tf). Because we distribute entropy, we do not want to use inverse
			 * document frequency(idf) either!
			 */
			if (!(this instanceof EntropyBasedCveClassifier)) {
				stringToWordFilter.setTFTransform(true);
				stringToWordFilter.setIDFTransform(true);
				stringToWordFilter.setOutputWordCounts(true);
			}
			if (useNGrams) {
				NGramTokenizer tokenizer = new NGramTokenizer();
				tokenizer.setNGramMinSize(1);
				tokenizer.setNGramMaxSize(3);
				tokenizer.setDelimiters(" ");
				stringToWordFilter.setTokenizer(tokenizer); // set tokenizer!
			}
			stringToWordFilter.setInputFormat(myInstances);
			myInstances = Filter.useFilter(myInstances, stringToWordFilter);

			logger.info("StringToWordVector filter applied: " + "# of attributes changed from " + attribCount + " to " + myInstances.numAttributes() + " UsedNGrams: " + useNGrams);
		} catch (Exception e) {
			logger.error(e.toString());
		}
		return myInstances;
	}

	/**
	 * Create an Instance from a comma separated string
	 * 
	 * @param myInstances            The instances to add the new instance
	 * @param sCommaSeparatedAttribs Comma separated string that stores attribs
	 * @param classIsmissing         sCommaSeparatedAttribs does not include the
	 *                               class attrib
	 * @return Created instance
	 */
	protected Instance createInstanceFromCommaSeparatedAttribs(String sCommaSeparatedAttribs, boolean classIsmissing) {

		DenseInstance currentInstance = null;
		try {

			String[] attribs = sCommaSeparatedAttribs.split(",");
			int numberOfAttribs = myInstances.numAttributes();
			double[] instanceValues = new double[numberOfAttribs];

			// set numeric attribs: store nominal attrib indexes
			ArrayList<Integer> nominalIndexList = new ArrayList<Integer>();

			for (int i = 1; i < numberOfAttribs - 1; i++) {

				try {
					String sToken = myInstances.attribute(i).name();
					if (sCommaSeparatedAttribs.indexOf(sToken) >= 0) {
						// binary
						instanceValues[i] = 1;

					}

				} catch (Exception e) {
					logger.error("Could not parse " + attribs[i] + ", attrib is nominal?");
					instanceValues[i] = 0;
					nominalIndexList.add(i);
				}
			}

			currentInstance = new DenseInstance(1.0, instanceValues);
			currentInstance.setDataset(myInstances);

			/**
			 * assign non numeric values if the index of non-numeric attrib is 3, the 3th
			 * index of currentInstance becomes attrib[3]
			 */
			for (int i = 0; i < nominalIndexList.size(); i++) {
				int nominalAttributeIndex = nominalIndexList.get(i);
				currentInstance.setValue(nominalAttributeIndex, attribs[nominalAttributeIndex]);
			}

			if (classIsmissing) {
				currentInstance.setMissing(0); // set last value as ?
			} else {
				String value = attribs[attribs.length - 1]; // get last value from attribs array

				if (myInstances.classAttribute().indexOfValue(value + "") == -1) {
					// this new class does not exist among the current classes, so add it!!
					myInstances = addValueToClassAttrib(myInstances, value + "");
					currentInstance.setDataset(myInstances);
				}

				int index = myInstances.classAttribute().indexOfValue(value + "");
				currentInstance.setValue(currentInstance.numAttributes() - 1, index);
			}

		} catch (Exception e) {
			logger.error(e.toString());
			currentInstance = null;
		}

		return currentInstance;
	}

	/**
	 * Add a new class label
	 * 
	 * @param instances
	 * @param value
	 * @return
	 */
	protected Instances addValueToClassAttrib(Instances instances, String value) {

		try {
			AddValues addValueFilter = new AddValues();
			String classIndex = instances.numAttributes() + ""; // the index starts from 1
			addValueFilter.setAttributeIndex(classIndex);
			addValueFilter.setLabels(value);
			addValueFilter.setInputFormat(instances);

			instances = Filter.useFilter(instances, addValueFilter);
		} catch (Exception e) {
			logger.error(e.toString());
			e.printStackTrace();
		}
		return instances;
	}

	protected Instances getMyInstances() {
		return myInstances;
	}

	public boolean getTestMultiClassPrediction() {
		return testMultiClassPrediction;
	}

	public String getCveClassifierName() {
		return cveClassifierName;
	}

	public void setCveClassifierName(String cveClassifierName) {
		this.cveClassifierName = cveClassifierName;
	}

	public void dumpData(String filePath) {
		try {
			BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
			writer.write(myInstances.toString());
			writer.flush();
			writer.close();
		} catch (IOException e) {
			logger.error(e.toString());
		}
	}

	public String convertCSVtoARFF(String csvFile) {
		String myARFFFile = null;

		try {
			// load CSV
			CSVLoader loader = new CSVLoader();
			loader.setSource(new File(csvFile));
			Instances data = loader.getDataSet();

			// construct a name for arff
			myARFFFile = csvFile.replaceAll(".csv", "") + ".arff";

			// save ARFF
			BufferedWriter writer = new BufferedWriter(new FileWriter(myARFFFile));
			writer.write(data.toString());
			writer.flush();
			writer.close();
		} catch (IOException e) {
			logger.error("Error converting csv {} to arff! {}", csvFile, e.toString());
			return null;
		}
		return myARFFFile;
	}
}
