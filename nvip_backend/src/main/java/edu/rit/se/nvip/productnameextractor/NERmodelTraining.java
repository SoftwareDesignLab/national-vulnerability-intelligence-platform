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
package edu.rit.se.nvip.productnameextractor;

import java.io.File;
import java.io.IOException;

/**
 * NERmodelTraining class for training NER model
 * 
 * @author Igor Khokhlov
 *
 */

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.datavec.api.records.reader.SequenceRecordReader;
import org.datavec.api.records.reader.impl.csv.CSVSequenceRecordReader;
import org.datavec.api.split.NumberedFileInputSplit;
import org.deeplearning4j.datasets.datavec.SequenceRecordReaderDataSetIterator;
import org.deeplearning4j.nn.conf.GradientNormalization;
import org.deeplearning4j.nn.conf.MultiLayerConfiguration;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.layers.LSTM;
import org.deeplearning4j.nn.conf.layers.RnnOutputLayer;
import org.deeplearning4j.nn.conf.layers.recurrent.Bidirectional;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.nn.weights.WeightInit;
import org.deeplearning4j.optimize.api.InvocationType;
import org.deeplearning4j.optimize.listeners.EvaluativeListener;
import org.deeplearning4j.optimize.listeners.ScoreIterationListener;
import org.nd4j.evaluation.classification.Evaluation;
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.dataset.api.preprocessor.DataNormalization;
import org.nd4j.linalg.dataset.api.preprocessor.NormalizerStandardize;
import org.nd4j.linalg.dataset.api.preprocessor.serializer.NormalizerSerializer;
import org.nd4j.linalg.learning.config.Nadam;
import org.nd4j.linalg.lossfunctions.LossFunctions;

/**
 * This class is for NER model training
 * @author Igor Khokhlov
 *
 */

public class NERmodelTraining {
	
	private static Logger logger = LogManager.getLogger(NERmodelTraining.class);
	
	
	/**
	 * Trains the NER model
	 * @param String a folder with training and test data
	 * @param String model data file path
	 * @param String Normalizer model data path
	 * @param String Length of the input feature vector
	 * @param String Number of epochs
	 * @param String Number of classes
	 * @param String Batch size
	 * 
	 * Calling examples:
	 * d:\RIT\NVIP\NER_DATA d:\RIT\NVIP\NER_models\NERmodel.bin d:\RIT\NVIP\NER_models\NERnorm.bin 300 20 3 50
	 * 
	 * Structure of the data folder is following:
	 * DataPath:
	 * 			test:
	 * 				features:
	 * 				labels:
	 * 			train:
	 *  			features:
	 * 				labels:
	 */		
	public static void main(String[] args) {
		
		if (args.length != 7) {
			logger.error("Incorrect number of arguments!");
			return;
		}
		
		String dataPath = args[0];
		String trainPathData = dataPath + "\\train\\features\\";
		String trainPathLabels = dataPath + "\\train\\labels\\";
		String testPathData = dataPath + "\\test\\features\\";
		String testPathLabels = dataPath + "\\test\\labels\\";
		String modelPath = args[1];
		String normalizerPath=args[2];
		
		int inputLength, miniBatchSize, numLabelClasses, nEpochs;
        
		try {
			inputLength = Integer.parseInt(args[3]);
	        miniBatchSize = Integer.parseInt(args[6]);
	        numLabelClasses = Integer.parseInt(args[5]);
	        nEpochs = Integer.parseInt(args[4]);
		} catch (Exception e) {
			logger.error(e);
			return;
		}
		
		//check if NER model folder exists and create if it does not
		String modelFolder = new File(modelPath).getParent();
		File directory = new File(modelFolder);
		if (! directory.exists()){
			logger.info("Creating NER model folders...");
	        directory.mkdirs();
	    }
		
		//check if normalizer model folder exists and create if it does not
		String modelNormFolder = new File(normalizerPath).getParent();
		File normDirectory = new File(modelNormFolder);
		if (! normDirectory.exists()){
			logger.info("Creating normalizer model folders...");
			normDirectory.mkdirs();
	    }
	
		//Get number of training files
		int trainDataSize = new File(trainPathData).listFiles().length;
		logger.info("Training data has " + Integer.toString(trainDataSize) + " files.");
		
		// ----- Load the training data -----
		SequenceRecordReader trainFeatures = new CSVSequenceRecordReader(0, ",");
		try {
			trainFeatures.initialize(new NumberedFileInputSplit(trainPathData + "/%d.csv", 0, trainDataSize-1));
		} catch (IOException | InterruptedException e) {
			logger.error(e);
		} 
        SequenceRecordReader trainLabels = new CSVSequenceRecordReader();
        try {
			trainLabels.initialize(new NumberedFileInputSplit(trainPathLabels + "/%d.csv", 0, trainDataSize-1));
		} catch (IOException | InterruptedException e) {
			logger.error(e);
		}
        
        DataSetIterator trainData = new SequenceRecordReaderDataSetIterator(trainFeatures, trainLabels, miniBatchSize, numLabelClasses,
                false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);
            
        //Normalize the training data
        DataNormalization normalizer = new NormalizerStandardize();
        normalizer.fit(trainData);              //Collect training data statistics
        trainData.reset();

        NormalizerSerializer saver = NormalizerSerializer.getDefault();
        File normalsFile = new File(normalizerPath);
        try {
			saver.write(normalizer,normalsFile);
			logger.info("Normalization model is saved.");
		} catch (IOException e) {
			logger.error(e);
		}
        
        logger.info("Normalization is completed...");
        
        //Use previously collected statistics to normalize on-the-fly. Each DataSet returned by 'trainData' iterator will be normalized
        trainData.setPreProcessor(normalizer);
        
        // ----- Load the test data -----
        
        //Get number of training files
      	int testDataSize = new File(testPathData).listFiles().length;
      	logger.info("Test data has " + Integer.toString(testDataSize) + " files.");
        
        //Same process as for the training data.
        SequenceRecordReader testFeatures = new CSVSequenceRecordReader(0, ",");
        try {
			testFeatures.initialize(new NumberedFileInputSplit(testPathData + "/%d.csv", 0, testDataSize-1));
		} catch (IOException | InterruptedException e) {
			logger.error(e);
		} 
        SequenceRecordReader testLabels = new CSVSequenceRecordReader();
        try {
			testLabels.initialize(new NumberedFileInputSplit(testPathLabels + "/%d.csv", 0, testDataSize-1));
		} catch (IOException | InterruptedException e) {
			logger.error(e);
		}

        DataSetIterator testData = new SequenceRecordReaderDataSetIterator(testFeatures, testLabels, miniBatchSize, numLabelClasses,
            false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

        testData.setPreProcessor(normalizer);   //Note that we are using the exact same normalization process as the training data
        
        // ----- Configure the network -----
        MultiLayerConfiguration conf = new NeuralNetConfiguration.Builder()
                .seed(123)    //Random number generator seed for improved repeatability. Optional.
                .weightInit(WeightInit.RELU)
                .updater(new Nadam())
                .gradientNormalization(GradientNormalization.ClipElementWiseAbsoluteValue)  //Not always required, but helps with this data set
                .gradientNormalizationThreshold(0.5)
                .list()
                .layer(new Bidirectional(new LSTM.Builder().activation(Activation.TANH).nIn(inputLength).nOut(300).build()))
                .layer(new RnnOutputLayer.Builder(LossFunctions.LossFunction.MCXENT)
                        .activation(Activation.SOFTMAX).nIn(600).nOut(numLabelClasses).build())
                .build();
    
 
        MultiLayerNetwork net = new MultiLayerNetwork(conf);
        net.init();
        
        logger.info("Training parameters are:");
        logger.info("Input size is " + Integer.toString(inputLength));
        logger.info("Batch size is " + Integer.toString(miniBatchSize));
        logger.info("Number of epochs is " + Integer.toString(nEpochs));
           
        logger.info("Starting training...");
        net.setListeners(new ScoreIterationListener(20), new EvaluativeListener(testData, 1, InvocationType.EPOCH_END));   //Print the score (loss function value) every 20 iterations

        net.fit(trainData, nEpochs);
        
        logger.info("Evaluating...");
        Evaluation eval = net.evaluate(testData);
        logger.info(eval.stats());
        
        logger.info("Saving model...");
        try {
			net.save(new File(modelPath));
		} catch (IOException e) {
			logger.error(e);
		}

        logger.info("Training is complete!");
	}
}
