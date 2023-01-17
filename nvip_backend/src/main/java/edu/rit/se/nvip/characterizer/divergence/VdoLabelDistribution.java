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
package edu.rit.se.nvip.characterizer.divergence;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.math3.util.FastMath;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import weka.core.Instance;
import weka.core.Instances;

/**
 * @author axoeec
 *
 */
public class VdoLabelDistribution {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private String vdoLabel = null;
	private Map<String, Integer> histogram = new HashMap<>();
	int nTotCount = 0;
	double nBaseCount = 171476; // the # of English words in corpus

	double entropy;

	/**
	 * generate a feature histogram for the given vdo label by filtering given
	 * instances
	 * 
	 * @param classLabel
	 * @param data
	 */
	public VdoLabelDistribution(String classLabel, Instances data) {
		this.vdoLabel = classLabel;

		int numInstances = data.numInstances();
		for (int insIndex = 0; insIndex < numInstances; insIndex++) {
			Instance currInst = data.instance(insIndex);
			String label = currInst.stringValue(currInst.classAttribute());
			if (label.equalsIgnoreCase(classLabel))
				histogram = addInstance(histogram, currInst);
		}

		// tot observations in my histogram
		nTotCount = getTotalNumberOfFrequencies();

		// the entropy [0-1]
		entropy = calculateEntropy(nTotCount);

		nBaseCount = data.numAttributes() - 1;
	}

	/**
	 * add an instance to my histogram
	 * 
	 * @param histogram
	 * @param currInst
	 * @return
	 */
	public Map<String, Integer> addInstance(Map<String, Integer> histogram, Instance currInst) {
		int numAttrs = currInst.numAttributes();
		for (int attrIndex = 0; attrIndex < numAttrs; attrIndex++) {
			if (attrIndex == currInst.classIndex())
				continue;
			String key = currInst.attribute(attrIndex).name();
			int value = (int) currInst.value(attrIndex);

			if (value == 0)
				continue;

			if (histogram.containsKey(key))
				histogram.put(key, histogram.get(key) + value);
			else
				histogram.put(key, value);
		}
		return histogram;
	}

	/**
	 * generate a histogram from a single instance
	 * 
	 * @param currInst
	 */
	public VdoLabelDistribution(Instance currInst) {
		histogram = addInstance(histogram, currInst);
		// tot observations in my histogram
		nTotCount = getTotalNumberOfFrequencies();

		// the entropy [0-1]
		entropy = calculateEntropy(nTotCount);

		nBaseCount = currInst.numAttributes() - 1;

	}

	public Map<String, Integer> getHistogram() {
		return histogram;

	}

	/**
	 * The frequency of the words (total observations)
	 * 
	 * @return
	 */
	private int getTotalNumberOfFrequencies() {
		int count = 0;
		for (Integer value : histogram.values()) {
			count += value;
		}
		return count;

	}

	/**
	 * cross entropy between the <cveHistogram> and this cve model histogram
	 * 
	 * // int numOfFeatureValuesInModel = cveModelHistogram.size(); // double
	 * modelEntropyForFeature = getEntropy(); // double dRedistributedUnitEntropy =
	 * modelEntropyForFeature / nBaseCount; // double dTotalDistributedEntropy =
	 * (dRedistributedUnitEntropy * (nBaseCount - numOfFeatureValuesInModel)); // //
	 * // probability for model // q = 0; // if
	 * (cveModelHistogram.get(featureValueKey) != null) { // double realProb =
	 * cveModelHistogram.get(featureValueKey) / totalObservationsOnCveModel; //
	 * double epsilon = dTotalDistributedEntropy * realProb; // q = realProb -
	 * epsilon; // } else // q = dRedistributedUnitEntropy;
	 * 
	 * @param cveHistogram
	 * @param distributeEntropy TODO
	 * @return
	 */
	public double calculateCrossEntropy(VdoLabelDistribution cveHistogram, boolean distributeEntropy) {

		// cross entropy based on all features!

		// total alerts on the aggregate and model
		double totalObservationsOnCveModel = getTotalNumberOfFrequencies();

		double totalObservationsOnCveInstance = cveHistogram.getTotalNumberOfFrequencies();

		// Only needs the number of instances
		Map<String, Integer> cveInstanceHistogram = cveHistogram.getHistogram();
		Map<String, Integer> cveModelHistogram = getHistogram();

		double p, q;
		double individualCrossEntropy = 0;
		String sContent = "";
		for (HashMap.Entry<String, Integer> entry : cveInstanceHistogram.entrySet()) {
			String featureValueKey = entry.getKey();

			// probability for cve
			p = cveInstanceHistogram.get(featureValueKey) / totalObservationsOnCveInstance;

			// probability for label histogram (model)
			if (cveModelHistogram.get(featureValueKey) != null) {
				q = cveModelHistogram.get(featureValueKey) / totalObservationsOnCveModel;
			} else
				q = 0;

			if (distributeEntropy)
				q = q * (1 - getEntropy()) + getEntropy() / nBaseCount;

			individualCrossEntropy += p * FastMath.log(q);

		}

		return -1 * individualCrossEntropy;
	}

	/**
	 * KL divergence
	 * 
	 * @param cveHistogram
	 * @return
	 */
	public double calculateKLDivergence(VdoLabelDistribution cveHistogram) {
		double crossEntropy = calculateCrossEntropy(cveHistogram, true);
		int totalNumOfFrequencies = cveHistogram.getTotCount() + getTotCount();
		double cveEntropy = cveHistogram.calculateEntropy(totalNumOfFrequencies);
		return crossEntropy - cveEntropy;
	}

	/**
	 * entropy of this distribution
	 * 
	 * @param totalNumOfFrequencies
	 * @return
	 */
	private double calculateEntropy(int totalNumOfFrequencies) {

		double entropy = 0.0;
		Collection<Integer> values = histogram.values(); // Only needs the number of instances
		double p;
		for (Integer observedNum : values) {
			p = (double) observedNum / totalNumOfFrequencies;
			if (p == 0)
				continue;
			entropy += p * FastMath.log(p);
		}
		// normalize
		entropy = -1.0 * entropy / FastMath.log(totalNumOfFrequencies);
		return entropy;
	}

	/**
	 * JS Divergence
	 * 
	 * @param cveHistogram
	 * @return
	 */
	public double calculateJSDivergence(VdoLabelDistribution cveHistogram, boolean distributeEntropy) {
		Map<String, Integer> hashMapCveModel, hashMapSingleCve; // The hashmaps that are being compared, one hashmap from each model
		int totalFrequencyInCveModel, totalFrequencyInSingleCve; // Total number of features for a feature type
		Integer frequencyOnCveModel, frequencyOnSingleCve;
		double p, q, M; // Variables used in the calculation of JS Divergence
		double kldTerm1, kldTerm2; // Holds portions of the result before being added together

		// calculate JSD
		hashMapCveModel = getHistogram();
		hashMapSingleCve = cveHistogram.getHistogram();
		totalFrequencyInCveModel = getTotalNumberOfFrequencies();
		totalFrequencyInSingleCve = cveHistogram.getTotalNumberOfFrequencies();
		kldTerm1 = 0.0;
		kldTerm2 = 0.0;

		// 1/2 KL(P||M)
		for (Entry<String, Integer> entryCveModel : hashMapCveModel.entrySet()) {
			// Performs the calculation of KL Divergence with model 1 and the joint features
			frequencyOnCveModel = entryCveModel.getValue();
			frequencyOnSingleCve = hashMapSingleCve.get(entryCveModel.getKey());
			p = frequencyOnCveModel / (totalFrequencyInCveModel + 0.0);
			if (frequencyOnSingleCve != null) {
				q = frequencyOnSingleCve / (totalFrequencyInSingleCve + 0.0);
			} else {
				q = 0;
			}
			M = .5 * (p + q);
			kldTerm1 += p * FastMath.log(2, p / M);

		}
		// 1/2 KL(Q||M)
		for (Entry<String, Integer> entrySingleCve : hashMapSingleCve.entrySet()) {
			// Performs the calculation of KL Divergence with model 2 and the joint features
			frequencyOnCveModel = hashMapCveModel.get(entrySingleCve.getKey());
			frequencyOnSingleCve = entrySingleCve.getValue();
			if (frequencyOnCveModel != null) {
				p = frequencyOnCveModel / (totalFrequencyInCveModel + 0.0);
			} else {
				p = 0;
			}

			if (distributeEntropy)
				p = p * (1 - getEntropy()) + getEntropy() / nBaseCount;

			q = frequencyOnSingleCve / (totalFrequencyInSingleCve + 0.0);
			M = .5 * (p + q);
			kldTerm2 += q * FastMath.log(2, q / M);
		}
		return (.5 * (kldTerm1 + kldTerm2));
	}

	public String getVdoLabel() {
		return vdoLabel;
	}

	public double getEntropy() {
		return entropy;
	}

	public int getTotCount() {
		return nTotCount;
	}

}
