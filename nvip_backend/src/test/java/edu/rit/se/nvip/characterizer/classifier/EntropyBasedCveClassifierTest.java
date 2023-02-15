package edu.rit.se.nvip.characterizer.classifier;

import static org.junit.Assert.assertEquals;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.junit.Test;
import weka.core.*;

import java.util.ArrayList;

public class EntropyBasedCveClassifierTest {
    @Test
    public void testTrainMLModel() {
        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
        String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = trainingDataPath + trainingDataFileName;

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        EntropyBasedCveClassifier entropyBasedCveClassifier = new EntropyBasedCveClassifier(preProcessedTrainingDataFile);
        entropyBasedCveClassifier.trainMLModel();

        assertEquals(entropyBasedCveClassifier.histograms.size(), 4);
    }

    @Test
    public void testPredictIncorrectNumAttributes() {
        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
        String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = trainingDataPath + trainingDataFileName;

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        EntropyBasedCveClassifier entropyBasedCveClassifier = new EntropyBasedCveClassifier(preProcessedTrainingDataFile);

        Instance newInstance = new SparseInstance(293);
        ArrayList newList = entropyBasedCveClassifier.predict(newInstance, false);
        assertEquals(0, newList.size());
    }
}
