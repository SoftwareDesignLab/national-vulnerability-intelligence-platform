package edu.rit.se.nvip.characterizer.classifier;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.junit.Test;

public class EntropyBasedCveClassifierTest {
    @Test
    public void testResetClassifier() {
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

        EntropyBasedCveClassifier entropyBasedCveClassifier = new EntropyBasedCveClassifier();
    }
}
