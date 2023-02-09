package edu.rit.se.nvip.crawler;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertTrue;

public class QuickCveCrawlerTest {
	@Test
	public void testQuickCrawler() {
		QuickCveCrawler crawler = new QuickCveCrawler();
		List<CompositeVulnerability> list = crawler.getCVEsfromKnownSummaryPages();
		assertTrue(list.size() > 0);
	}

}
