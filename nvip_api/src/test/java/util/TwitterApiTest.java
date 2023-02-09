package util;

import static org.junit.Assert.assertEquals;

import org.junit.Test;


public class TwitterApiTest {
	@Test
	public void testTextChop() {
		TwitterApi tw = new TwitterApi();
		String str = "There is an Information Disclosure vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may impair data confidentiality.";
		String txt = tw.getTweetText("CVE-2021-22317", str);
		assertEquals(true, (txt.length() == 212));
	}

}
