package edu.rit.se.nvip.utils.email;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import edu.rit.se.nvip.automatedcvss.CvssScoreCalculator;

public class EmailDailyCveListTest {

	@Test
	public void emailTest() {
		EmailDailyCveList emailDailyCveList = new EmailDailyCveList();
		boolean sent = emailDailyCveList.sendCveNotificationEmailToSystemAdmin();
		assertEquals(true, sent);
	}

}
