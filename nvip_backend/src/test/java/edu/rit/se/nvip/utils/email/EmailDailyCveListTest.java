package edu.rit.se.nvip.utils.email;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class EmailDailyCveListTest {

	@Test
	public void emailTest() {
		EmailDailyCveList emailDailyCveList = new EmailDailyCveList();
		boolean sent = emailDailyCveList.sendCveNotificationEmailToSystemAdmin();
		assertTrue(sent);
	}

}
