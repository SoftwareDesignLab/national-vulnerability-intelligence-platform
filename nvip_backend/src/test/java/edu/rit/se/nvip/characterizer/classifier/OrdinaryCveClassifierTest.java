package edu.rit.se.nvip.characterizer.classifier;

import org.junit.Test;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.RandomForest;

import static org.junit.Assert.assertEquals;

public class OrdinaryCveClassifierTest {
    @Test
    public void testResetClassifier() {
        OrdinaryCveClassifier ordinaryCveClassifier = new OrdinaryCveClassifier();
        assertEquals(ordinaryCveClassifier.classifier.getClass(), Vote.class);
        ordinaryCveClassifier.resetClassifier(new RandomForest());
        assertEquals(ordinaryCveClassifier.classifier.getClass(), RandomForest.class);
    }
}