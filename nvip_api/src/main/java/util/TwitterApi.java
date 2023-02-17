/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the �Software�), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import opennlp.tools.sentdetect.SentenceDetectorME;
import opennlp.tools.sentdetect.SentenceModel;
import opennlp.tools.util.InvalidFormatException;
import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.conf.ConfigurationBuilder;

public class TwitterApi {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public static void main(String[] args) {

			TwitterApi tw = new TwitterApi();
		/*
			String str = "There is an Information Disclosure vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may impair data confidentiality.";
			tw.getTweetText("CVE-2021-1234", str);
		*/

		tw.postTweet("CVE-2000-1000", "TEST", false);
	}


	/**
	 * post a tweet
	 * 
	 * @param cveId
	 * @param cveDescription
	 * @param debug
	 */
	public void postTweet(String cveId, String cveDescription, boolean debug) {
		Twitter twitter = null;
		if (!debug) {
			twitter = getTwitterFromEnv();
			if(twitter != null){
				logger.error("Unable to connect to Twitter with Environment Variables. Attempting to search for Context.xml credentials");
				twitter = getTwitter();
				if (twitter == null) {
					logger.error("Could not connect Twitter! Check Twitter credentials in Context.xml under Tomcat!");
					return;
				}
			}
		}

		try {

			String str = getTweetText(cveId, cveDescription);
			if (!debug) {
				logger.info("Posting Tweet... tweet length {}, content {}", str.length(), str);
				twitter.updateStatus(str);
			}
		} catch (TwitterException e) {
			logger.error(e.toString());
			e.printStackTrace();
		}
	}

	/**
	 * Chop into sentences and generate tweet text
	 * 
	 * @param cveId
	 * @param cveDescription
	 * @return
	 */
	public String getTweetText(String cveId, String cveDescription) {
		final int TWEET_BODY_LENGTH = 200;
		String TWEET_TAIL = "- for more details: cve.live \n #cve #cybersecurity #infosec";

		cveDescription = cveDescription.replace("\"", ""); // remove quotes if any
		cveDescription = cveDescription.replace("\'", "");

		// split description into sentences
		String[] sentences = sentenceSplitterApacheOpenNlp(cveDescription);

		/**
		 * pick sentences till we reach tweet size limit, reserve last X chars for tail
		 */
		String str = cveId + ": " + sentences[0];
		if (str.length() >= TWEET_BODY_LENGTH) {
			str = str.substring(0, TWEET_BODY_LENGTH);
		} else {
			for (int i = 1; i < sentences.length; i++) {
				if (str.length() + sentences[i].length() < TWEET_BODY_LENGTH)
					str += " " + sentences[i];
				else {
					// get part of last sentence
					int lastIndex = TWEET_BODY_LENGTH - str.length(); // remaining length
					str += " " + sentences[i].substring(0, lastIndex);

					break;
				}
			}
		}

		/**
		 * check if are we chopping words at the end!
		 */
		int lastIndex = str.length();
		while (str.charAt(lastIndex - 1) != ' ')
			lastIndex--; // find space, not to chop words

		if (lastIndex != str.length())
			str = str.substring(0, lastIndex);

		//add tail
		str += " ...";
		str += TWEET_TAIL;

		logger.info("Tweet length {}, content {}", str.length(), str);

		return str;
	}

	/**
	 * get twitter object
	 * 
	 * @return
	 */
	private Twitter getTwitter() {

		try {
			InitialContext initialContext = new InitialContext();
			Context environmentContext = (Context) initialContext.lookup("java:/comp/env");
			String consumerKey = (String) environmentContext.lookup("consumerKey");
			String consumerSecret = (String) environmentContext.lookup("consumerSecret");
			String accessToken = (String) environmentContext.lookup("accessToken");
			String accessTokenSecret = (String) environmentContext.lookup("accessTokenSecret");

			ConfigurationBuilder cb = new ConfigurationBuilder();
			cb.setDebugEnabled(true).setOAuthConsumerKey(consumerKey).setOAuthConsumerSecret(consumerSecret).setOAuthAccessToken(accessToken).setOAuthAccessTokenSecret(accessTokenSecret);
			TwitterFactory tf = new TwitterFactory(cb.build());
			return tf.getInstance();
		} catch (NamingException e) {
			logger.error(e.toString());
		}

		return null;
	}

	/***
	 * Create a Twitter Object using environment variables
	 * @return Twitter
	 */
	private Twitter getTwitterFromEnv() {
		String consumerKey = System.getenv("consumerKey");
		String consumerSecret = System.getenv("consumerSecret");
		String accessToken = System.getenv("accessToken");
		String accessTokenSecret = System.getenv("accessTokenSecret");

		ConfigurationBuilder cb = new ConfigurationBuilder();
		cb.setDebugEnabled(true).setOAuthConsumerKey(consumerKey).setOAuthConsumerSecret(consumerSecret).setOAuthAccessToken(accessToken).setOAuthAccessTokenSecret(accessTokenSecret);
		TwitterFactory tf = new TwitterFactory(cb.build());
		return tf.getInstance();
	}

	private void sentenceSplitterRegex(String str) {
		String[] parts = str.split("(?<=[.!?]|[.!?][\\'\\\"])\\s+");
		for (String sentence : parts)
			logger.info(sentence);
	}

	public String[] sentenceSplitterApacheOpenNlp(String paragraph) {
		/**
		 * Model file "en-sent.bin", available at
		 * http://opennlp.sourceforge.net/models-1.5/
		 */
		try (InputStream is = getClass().getResourceAsStream("/en-sent.bin");) {
			SentenceModel model = new SentenceModel(is);

			// feed the model to SentenceDetectorME class
			SentenceDetectorME sdetector = new SentenceDetectorME(model);
			String sentences[] = sdetector.sentDetect(paragraph);
			for (int i = 0; i < sentences.length; i++) {
				logger.info(sentences[i]);
			}
			return sentences;

		} catch (Exception e) {
			logger.error(e.toString());
			e.printStackTrace();
		}
		return null;
	}

}
