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
package edu.rit.se.nvip.cvss.utils;

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.deeplearning4j.iterator.CnnSentenceDataSetIterator;
import org.deeplearning4j.iterator.LabeledSentenceProvider;
import org.deeplearning4j.iterator.provider.FileLabeledSentenceProvider;
import org.deeplearning4j.models.embeddings.wordvectors.WordVectors;
import org.deeplearning4j.nn.conf.ComputationGraphConfiguration;
import org.deeplearning4j.nn.conf.ConvolutionMode;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.graph.MergeVertex;
import org.deeplearning4j.nn.conf.layers.ConvolutionLayer;
import org.deeplearning4j.nn.conf.layers.GlobalPoolingLayer;
import org.deeplearning4j.nn.conf.layers.GravesLSTM;
import org.deeplearning4j.nn.conf.layers.LSTM;
import org.deeplearning4j.nn.conf.layers.OutputLayer;
import org.deeplearning4j.nn.conf.layers.PoolingType;
import org.deeplearning4j.nn.conf.layers.RnnOutputLayer;
import org.deeplearning4j.nn.conf.preprocessor.CnnToRnnPreProcessor;
import org.deeplearning4j.nn.conf.preprocessor.RnnToCnnPreProcessor;
import org.deeplearning4j.nn.graph.ComputationGraph;
import org.deeplearning4j.nn.weights.WeightInit;
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.learning.config.Adam;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.nd4j.linalg.lossfunctions.LossFunctions.LossFunction;

import weka.core.Instance;
import weka.core.Instances;

/**
 * Utilities for ComputationGraph
 * 
 * @author axoeec
 *
 */
public class CompGraphDataUtils {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * init model
	 * 
	 * @param dataLabels
	 * @param multiclass TODO
	 * @return
	 */
	public ComputationGraph initDLCNNNet(List<String> dataLabels, boolean multiclass) {

		// pooling
		PoolingType globalPoolingType = PoolingType.MAX;

		// loss function
		LossFunction lossFunction = LossFunctions.LossFunction.MCXENT;
		if (!multiclass)
			lossFunction = LossFunctions.LossFunction.XENT;

		// activation
		Activation activation = Activation.SOFTMAX;
		if (!multiclass)
			activation = Activation.SIGMOID;

		/**
		 * Set up the network configuration. Multiple CNN layers, each with filter
		 * widths of 3, 4 and 5.
		 * 
		 * Note that the size of the output layer is equal to the number of labels! Also
		 * note the global pool with MAX pooling at the end of the 3 CNN layers.
		 */

		int vectorSize = ModelParams.getVectorsize();
		int cnnLayerFeatureMaps = ModelParams.getCnnlayerfeaturemaps();
		Nd4j.getMemoryManager().setAutoGcWindow(5000);
		ComputationGraphConfiguration config = new NeuralNetConfiguration.Builder().weightInit(WeightInit.RELU).activation(Activation.LEAKYRELU).updater(new Adam(0.01)).convolutionMode(ConvolutionMode.Same) // This is important so we can
																																																				// 'stack' the results later
				.l2(0.0001).graphBuilder().addInputs("input").addLayer("cnn3", new ConvolutionLayer.Builder().kernelSize(3, vectorSize).stride(1, vectorSize).nIn(1).nOut(cnnLayerFeatureMaps).build(), "input")
				.addLayer("cnn4", new ConvolutionLayer.Builder().kernelSize(4, vectorSize).stride(1, vectorSize).nIn(1).nOut(cnnLayerFeatureMaps).build(), "input")
				.addLayer("cnn5", new ConvolutionLayer.Builder().kernelSize(5, vectorSize).stride(1, vectorSize).nIn(1).nOut(cnnLayerFeatureMaps).build(), "input").addVertex("merge", new MergeVertex(), "cnn3", "cnn4", "cnn5") // Perform
																																																									// depth
																																																									// concatenation
				.addLayer("globalPool", new GlobalPoolingLayer.Builder().poolingType(globalPoolingType).dropOut(0.5).build(), "merge")
				.addLayer("out", new OutputLayer.Builder().lossFunction(lossFunction).activation(activation).nIn(3 * cnnLayerFeatureMaps).nOut(dataLabels.size()).build(), "globalPool").setOutputs("out").build();

		ComputationGraph net = new ComputationGraph(config);
		net.init();

		return net;
	}

	/**
	 * init model for exploitability prediction
	 * 
	 * @param dataLabels
	 * @param multiclass
	 * @return
	 */
	public ComputationGraph initDLCNNNetForExploitability(List<String> dataLabels, boolean multiclass) {

		// pooling
		PoolingType globalPoolingType = PoolingType.MAX;

		// loss function
		LossFunction lossFunction = LossFunctions.LossFunction.MCXENT;
		if (!multiclass)
			lossFunction = LossFunctions.LossFunction.XENT;

		// activation
		Activation activation = Activation.SOFTMAX;
		if (!multiclass)
			activation = Activation.SIGMOID;

		/**
		 * Set up the network configuration. Multiple CNN layers, each with filter
		 * widths of 3, 4 and 5.
		 * 
		 * Note that the size of the output layer is equal to the number of labels! Also
		 * note the global pool with MAX pooling at the end of the 3 CNN layers.
		 */

		final int lstmLayerSize = 300;

		int vectorSize = ModelParams.getVectorsize();
		int cnnLayerFeatureMaps = ModelParams.getCnnlayerfeaturemaps();
		Nd4j.getMemoryManager().setAutoGcWindow(5000);
		ComputationGraphConfiguration config = new NeuralNetConfiguration.Builder().weightInit(WeightInit.RELU).activation(Activation.LEAKYRELU).updater(new Adam(0.001)).convolutionMode(ConvolutionMode.Same) // This is important so we can
																																																				// 'stack' the results later
				.l2(0.001).graphBuilder().addInputs("input")

				// .addLayer("cnn1", new ConvolutionLayer.Builder().kernelSize(1,
				// vectorSize).stride(1, vectorSize).nIn(1).nOut(cnnLayerFeatureMaps).build(),
				// "input")
				.addLayer("cnn2", new ConvolutionLayer.Builder().kernelSize(2, vectorSize).stride(1, vectorSize).nIn(1).nOut(cnnLayerFeatureMaps).build(), "input")
				.addLayer("cnn3", new ConvolutionLayer.Builder().kernelSize(3, vectorSize).stride(1, vectorSize).nIn(1).nOut(cnnLayerFeatureMaps).build(), "input")
				.addLayer("cnn4", new ConvolutionLayer.Builder().kernelSize(4, vectorSize).stride(1, vectorSize).nIn(1).nOut(cnnLayerFeatureMaps).build(), "input")
//				.addLayer("cnn5", new ConvolutionLayer.Builder().kernelSize(5, vectorSize).stride(1, vectorSize).nIn(1).nOut(cnnLayerFeatureMaps).build(), "input")
//				.addLayer("cnn6", new ConvolutionLayer.Builder().kernelSize(6, vectorSize).stride(1, vectorSize).nIn(1).nOut(cnnLayerFeatureMaps).build(), "input")

				.addVertex("merge", new MergeVertex(), "cnn2", "cnn3", "cnn4") // Perform depth concatenation

				.addLayer("globalPool", new GlobalPoolingLayer.Builder().poolingType(globalPoolingType).dropOut(0.5).build(), "merge")
				.addLayer("out", new OutputLayer.Builder().lossFunction(lossFunction).activation(activation).nIn(3 * cnnLayerFeatureMaps).nOut(dataLabels.size()).build(), "globalPool")

//				 .addLayer("lstm", new LSTM.Builder()
//			                .nIn(4*cnnLayerFeatureMaps)
//			                .nOut(lstmLayerSize)
//			                .forgetGateBiasInit(1)
//			                .activation(Activation.TANH)
//			                .build(),
//			                "globalPool")
//				 
//				 
//				.addLayer("out", new RnnOutputLayer.Builder().lossFunction(lossFunction).activation(activation).nIn(lstmLayerSize).nOut(dataLabels.size()).build(), "lstm")
//				.inputPreProcessor("lstm", new CnnToRnnPreProcessor(4, 1,10))

				.setOutputs("out").build();

		ComputationGraph net = new ComputationGraph(config);
		net.init();

		return net;
	}

	/**
	 * Prepare the data for the CNN DL model, using the provided arff file
	 * 
	 * @param arffDataPath
	 */
	public void prepareData(String basePath, String arffDataPath) {

		String dirName = arffDataPath.substring(arffDataPath.lastIndexOf("/"), arffDataPath.indexOf(".arff"));

		String dataRoot = basePath + "/" + dirName;
		File theDir = new File(dataRoot);

		// if the directory does not exist, create it
		if (!theDir.exists())
			theDir.mkdir();

		try {
			/**
			 * prepare data
			 */
			Instances instances = new Instances(new FileReader(arffDataPath));
			instances.setClassIndex(instances.numAttributes() - 1);
			instances.deleteWithMissingClass();

			/**
			 * create a dir for each class label
			 */
			int classCount = instances.classAttribute().numValues();
			for (int i = 0; i < classCount; i++) {
				String label = instances.classAttribute().value(i);
				File subDir = new File(dataRoot + "/" + label);
				if (!subDir.exists())
					subDir.mkdir();
			}

			/**
			 * copy files under their corresponding dirs
			 */
			int index = 1;
			for (Instance instance : instances) {
				String txt = instance.stringValue(instance.attribute(0));
				String classVal = instance.stringValue(instance.classAttribute());
				String path = dataRoot + "/" + classVal + "/" + index + ".txt";
				FileUtils.writeStringToFile(new File(path), txt);
				index++;
			}
		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.toString());
		}
	}

	/**
	 * Get data set from the provided dataPath
	 * 
	 * @param labels
	 * @param dataPath
	 * @param wordVectors
	 * @param minibatchSize
	 * @param maxSentenceLength
	 * @param rng
	 * @return
	 */
	public DataSetIterator getDataSetIterator(List<String> labels, String dataPath, WordVectors wordVectors, int minibatchSize, int maxSentenceLength, Random rng) {

		List<String> dirs = new ArrayList<String>();

		for (String label : labels)
			dirs.add(dataPath + "/" + label);

		List<File> files = new ArrayList<File>();
		for (String dir : dirs)
			files.add(new File(dir));

		Map<String, List<File>> filesMap = new HashMap<>();
		for (int i = 0; i < files.size(); i++) {
			filesMap.put(labels.get(i), Arrays.asList(files.get(i).listFiles()));
		}

		LabeledSentenceProvider sentenceProvider = new FileLabeledSentenceProvider(filesMap, rng);
//		return new CnnSentenceDataSetIterator.Builder().sentenceProvider(sentenceProvider).wordVectors(wordVectors).minibatchSize(minibatchSize)
//				.maxSentenceLength(maxSentenceLength).useNormalizedWordVectors(false).build();

		return new CnnSentenceDataSetIterator.Builder().sentenceProvider(sentenceProvider).wordVectors(wordVectors).minibatchSize(minibatchSize).maxSentenceLength(maxSentenceLength).useNormalizedWordVectors(true).build();
	}
}
