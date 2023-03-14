package edu.rit.se.nvip.crawler;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.CrawlController;
import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.frontier.FrontierConfiguration;
import edu.uci.ics.crawler4j.frontier.SleepycatFrontierConfiguration;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtConfig;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtServer;
import crawlercommons.filters.basic.BasicURLNormalizer;
import edu.uci.ics.crawler4j.url.SleepycatWebURLFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CveCrawlController {

    private static final Logger logger = LogManager.getLogger(CveCrawlController.class.getSimpleName());
    MyProperties properties = new PropertyLoader().loadConfigFile(new MyProperties());

    public static void main(String[] args) throws Exception {
        new CveCrawlController().crawl(new ArrayList<>());
    }

    public HashMap<String, CompositeVulnerability> crawl(List<String> urls) throws Exception {

        CrawlConfig config1 = new CrawlConfig();
        CrawlConfig config2 = new CrawlConfig();

        config1.setCrawlStorageFolder(properties.getDataDir() + "");
        config2.setCrawlStorageFolder(properties.getDataDir() + "");

        config1.setPolitenessDelay(properties.getDefaultCrawlerPoliteness());
        config2.setPolitenessDelay(properties.getDelayedCrawlerPoliteness());

        config1.setMaxPagesToFetch(10);
        config2.setMaxPagesToFetch(100);

        config1.setMaxDepthOfCrawling(properties.getCrawlSearchDepth());
        config2.setMaxDepthOfCrawling(properties.getCrawlSearchDepth());

        BasicURLNormalizer normalizer1 = BasicURLNormalizer.newBuilder().idnNormalization(BasicURLNormalizer.IdnNormalization.NONE).build();
        BasicURLNormalizer normalizer2 = BasicURLNormalizer.newBuilder().idnNormalization(BasicURLNormalizer.IdnNormalization.NONE).build();
        PageFetcher pageFetcher1 = new PageFetcher(config1, normalizer1);
        PageFetcher pageFetcher2 = new PageFetcher(config2, normalizer2);

        RobotstxtConfig robotstxtConfig = new RobotstxtConfig();

        FrontierConfiguration frontierConfiguration = new SleepycatFrontierConfiguration(config1);
        FrontierConfiguration frontierConfiguration2 = new SleepycatFrontierConfiguration(config2);

        RobotstxtServer robotstxtServer = new RobotstxtServer(robotstxtConfig, pageFetcher1, new SleepycatWebURLFactory());

        CrawlController controller1 = new CrawlController(config1, normalizer1, pageFetcher1, robotstxtServer, frontierConfiguration);
        CrawlController controller2 = new CrawlController(config2, normalizer2, pageFetcher2, robotstxtServer, frontierConfiguration2);

        ArrayList<String> domains = new ArrayList<>();
        domains.add("https://www.ics.uci.edu/");
        domains.add("https://www.cnn.com/");

        List<String> crawler1Domains = domains;

        controller1.addSeed("https://www.ics.uci.edu/");
        controller1.addSeed("https://www.cnn.com/");
        controller1.addSeed("https://www.ics.uci.edu/~lopes/");
        controller1.addSeed("https://www.cnn.com/POLITICS/");

        controller2.addSeed("https://en.wikipedia.org/wiki/Main_Page");
        controller2.addSeed("https://en.wikipedia.org/wiki/Obama");
        controller2.addSeed("https://en.wikipedia.org/wiki/Bing");

        MyProperties finalProperties1 = properties;
        CrawlController.WebCrawlerFactory<CveCrawler> factory1 = () -> new CveCrawler(finalProperties1);
        CrawlController.WebCrawlerFactory<CveCrawler> factory2 = () -> new CveCrawler(finalProperties1);

        // The first crawler will have 5 concurrent threads and the second crawler will have 7 threads.
        controller1.startNonBlocking(factory1, 5);
        //controller2.startNonBlocking(factory2, 7);

        controller1.waitUntilFinish();
        logger.info("Crawler 1 is finished.");

        //controller2.waitUntilFinish();
        //logger.info("Crawler 2 is finished.");
        return null;
    }

}