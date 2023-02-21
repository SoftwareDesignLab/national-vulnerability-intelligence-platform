package edu.rit.se.nvip.characterizer.classifier;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.junit.Test;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.RandomForest;
import weka.core.Instance;
import weka.core.SparseInstance;

import java.util.ArrayList;

import static org.junit.Assert.assertEquals;

public class OrdinaryCveClassifierTest {
    @Test
    public void testResetClassifier() {
        OrdinaryCveClassifier ordinaryCveClassifier = new OrdinaryCveClassifier();
        assertEquals(ordinaryCveClassifier.classifier.getClass(), Vote.class);
        ordinaryCveClassifier.resetClassifier(new RandomForest());
        assertEquals(ordinaryCveClassifier.classifier.getClass(), RandomForest.class);
    }

    @Test
    public void testPredictIncorrectNumAttr() {
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
        OrdinaryCveClassifier ordinaryCveClassifier = new OrdinaryCveClassifier(new RandomForest(), preProcessedTrainingDataFile);

        Instance newInstance = new SparseInstance(293);

        ArrayList<String[]> prediction = ordinaryCveClassifier.predict(newInstance, true);

        assertEquals(0, prediction.size());
    }
}